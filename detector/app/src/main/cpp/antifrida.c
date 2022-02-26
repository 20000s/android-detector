//
// Created by 24657 on 2022/2/24.
//

#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <dirent.h>
#include <ctype.h>
#include <stdbool.h>
#include <malloc.h>
#include <sys/stat.h>


typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;




static const char *FRIDA_THREAD_GUM_JS_LOOP = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR = "linjector";
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_FD = "/proc/self/fd";
static const char *PROC_TASK = "/proc/self/task";
#define LIBC "libc.so"

#define NUM_LIBS 1


typedef struct stExecSection {
    int execSectionCount;
    unsigned long offset[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;



static const char *libstocheck[NUM_LIBS] = { LIBC};
static execSection *elfSectionArr[NUM_LIBS] = {NULL};


/*
 *
 * 检测：1.检测ps 是否有frida_server (这个用不了 ps -A还是只有它自身)
 *      2.检查frida 端口 dbus (超级慢,得开另一个线程慢慢看   )
 *      3.通过 maps 查看内存可执行区域  寻找LIBFRIDA 或者map 看so frida-agent.so这个太简单了 不写了
 *      4.查看一些可能的线程 gmain、gum-js-loop
 *      5.检查管道 frida 进行注入的时候 会使用特定管道
 *      6.libc比对 因为frida用的是illine hook  hook前后 必然导致 文件的结构不同  因此可以进行校验
 *
 *
 * 防止frida HOOK :
 * 将libc map成只读
 *
 * 具体原理详见
 * https://github.com/TUGOhost/anti_Android
 */


/*

bool str_has_prefix(const char *str1, const char *str2) {
    //fixme, mem error
    const char *x = strstr(str1, str2);
    return x == str1;
}

// copy from https://github.com/frida/frida-core/blob/836d254614d836e39d17418e3b864c8b5862bf9b/src/linux/frida-helper-backend-glue.c#L3014
uint64_t frida_find_library_base(pid_t pid, const char *library_name, char **library_path) {
    uint64_t result = 0;
    char maps_path[1000];
    FILE *fp;
    const size_t line_size = 1024 + PATH_MAX;
    char *line, *path;

    if (library_path != NULL)
        *library_path = NULL;

    sprintf(maps_path, "/proc/%d/maps", pid);

    //maps_path = "/proc/self/maps";
    fp = fopen(maps_path, "r");


    line = malloc(line_size);
    path = malloc(PATH_MAX);

    while (result == 0 && fgets(line, line_size, fp) != NULL) {
        uint64_t start;
        int n;

        path[0] = 0;
        n = sscanf(line, "%"
                         PRIx64
                         "-%*x %*s %*x %*s %*s %s", &start, path);

        if (n != 2) {
            continue;
        }

        if (n == 1)
            continue;
//g_assert (n == 2);

        if (path[0] == '[')
            continue;

        if (strcmp(path, library_name) == 0) {
            result = start;
            if (library_path != NULL) {
                *library_path = strdup(path);
            }
        }

        else {
            char *p = strrchr(path, '/');
            if (p != NULL) {
                p++;

                if (str_has_prefix(p, library_name) && strstr(p, ".so")) {
                    char next_char = p[strlen(library_name)];
                    if (next_char == '-' || next_char == '.') {
                        result = start;
                        if (library_path != NULL)
                            *library_path = strdup(path);
                    }
                }
            }
        }
    }

    free(path);
    path = NULL;
    free(line);
    line = NULL;

    fclose(fp);
    fp = NULL;

    return result;
}

uint64_t frida_find_library_space_base(pid_t pid, uint64_t base,
                                       uint32_t page_size) {
    char maps_path[1000];
    FILE *fp;
    const size_t line_size = 1024 + 1024;
    char *line;

    sprintf(maps_path, "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    line = malloc(line_size);

    uint64_t last_end = 0;

    while (fgets(line, line_size, fp) != NULL) {
        uint64_t start;
        uint64_t end;
        int n;

        n = sscanf(line, "%"
                         PRIx64
                         "-%"
                         PRIx64
                         "", &start, &end);
        if (n != 2) {
            continue;
        }

        if (last_end == 0 && start == base) { // this is the first page
            last_end = start - page_size;
            break;
        }
        if (last_end == 0) { // always mmap after first entry
            last_end = end;
            continue;
        }
        if (start >= base) {
            last_end = 0;
            break;
        }

        if (start - page_size < last_end) {
            last_end = end;
            continue;
        }

        break;
    }

    free(line);
    line = NULL;

    fclose(fp);
    fp = NULL;

    return last_end;
}

void anti_frida() {
    char *path = NULL;
    int page_size = getpagesize();
    pid_t pid = getpid();
    uint64_t start = frida_find_library_base(pid, "libc", &path);

    if (start != 0 && path != NULL && strlen(path) > 0) {

        uint64_t base = frida_find_library_space_base(pid, start, page_size);

        if (base != 0) {
            int fd = open(path, O_RDONLY);
            free(path);
            path = NULL;
            if (fd > 0) {
                void *p = mmap((void *) base, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);

                if (p != MAP_FAILED) {
                    uint64_t start2 = frida_find_library_base(pid, "libc", NULL);
                    LOGD("mmap success ");
                } else {
                    LOGD("mmap failed");
                }
            }
        }
    }
}
*/

//int check_process_name(){
//    FILE * pfile = NULL;
//    char buf[1000] = {0};
//    pfile = popen("ps -A ","r");
//    if(pfile == NULL){
//        LOGD("cannot open ps");
//        return 0;
//    }
//    while (fgets(buf,sizeof(buf),pfile)){
//        LOGD("%s",buf);
//        char * stra = NULL;
//        stra = strstr(buf,"frida");
//        if(stra){
//            LOGD("found frida");
//            pclose(pfile);
//            return 1;
//        }
//    }
//    pclose(pfile);
//    return 0;
//}
//
   int check_frida_port() {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton("127.0.0.1", &(sa.sin_addr));

    int sock;

    int fd;
    char res[7];
    int num_found;
    int ret;
    int i;

    while (1) {

        /*
         * 1: Frida Server Detection.
         */

        for (i = 0; i <= 65535; i++) {

            sock = socket(AF_INET, SOCK_STREAM, 0);
            sa.sin_port = htons(i);

            if (connect(sock, (struct sockaddr *) &sa, sizeof sa) != -1) {
                memset(res, 0, 7);

                send(sock, "\x00", 1, 0);
                send(sock, "AUTH\r\n", 6, 0);

                usleep(100); // Give it some time to answer

                if ((ret = recv(sock, res, 6, MSG_DONTWAIT)) != -1) {
                    if (strcmp(res, "REJECT") == 0) {
                        LOGD("successful");
                    }
                }
            }

            close(sock);
        }
    }
}

int find_mem_string(unsigned long long start, unsigned long long end, char *bytes, unsigned int len) {

    char *pmem = (char*)start;
    int matched = 0;

    while ((unsigned long long)pmem <(unsigned long long) (end - len)) {

        if(*pmem == bytes[0]) {

            matched = 1;
            char *p = pmem + 1;

            while (*p == bytes[matched] && (unsigned long long)p < end) {
                matched ++;
                p ++;
            }

            if (matched >= len) {
                LOGD("foud frida");
                return 1;
            }
        }

        pmem ++;

    }
    return 0;
}


int scan_executable_segment(char * map) {
    char buf[512];
    unsigned long long start, end;

    sscanf(map, "%llx-%llx %s", &start, &end, buf);

    if (buf[2] == 'x'  && (strstr(map,".apk") == NULL)) {
        //LOGD("map %s",map);
       // LOGD("frida %llx %llx",start,end);
        return ((find_mem_string(start, end, (char *)"libfrida", 8) ));
    } else {
        return 0;
    }
}



int check_frida_maps(){
       char map[512] = {0};
       FILE *fd = NULL;
       int num_found = 0;
       fd = fopen("/proc/self/maps","r");
      if(fd != NULL){
      //   LOGD("okk");
           while (!feof(fd)){
               fgets(map,512,fd);
           //    LOGD("%s",map);
               if (scan_executable_segment(map) == 1) {
                   num_found++;

               }

           }
           if(num_found >=1){
               LOGD("found frida by maps");
               fclose(fd);
               return 1;
           }
       }else{
           LOGD("can not open maps");
       }

       return 0;

   }

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    memset(buf, 0, max_len);

    do {
        ret = read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}


   int check_frida_thread(){
       DIR * dir = opendir("/proc/self/task");

       if( dir != NULL){
           struct dirent * entry = NULL;

           while ((entry = readdir(dir)) != NULL){
               char filepath[256] = "";

               if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name,"..") == 0){
                   continue;
               }
               snprintf(filepath, sizeof(filepath), PROC_STATUS, entry->d_name);
               //LOGD("%s",filepath);
               int fd = openat(AT_FDCWD, filepath, O_RDONLY | O_CLOEXEC, 0);
               if(fd != 0 ){
                   char buf[512] = "";
                   read_one_line(fd,buf,512);
                   if(strstr(buf,FRIDA_THREAD_GMAIN)  || strstr(buf,FRIDA_THREAD_GUM_JS_LOOP)){
                       LOGD("find frida by thread");
                       close(fd);
                       closedir(dir);
                       return 1;
                   }
                   close(fd);

               }


           }
           closedir(dir);
       }else{
           LOGD("can not open task");
       }

       LOGD("frida threads no");

       return 0;

   }

   int check_frida_pipe(){
       DIR * dir = opendir(PROC_FD);
       if(dir != NULL){
           struct dirent * entry = NULL;
           while ((entry = readdir(dir)) != NULL){
               struct stat filestat;
               char buf[512] = "";
               char filePath[512] = "";
               snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);

               lstat(filePath, &filestat);

               if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                   //TODO: Another way is to check if filepath belongs to a path not related to system or the app
                   readlinkat(AT_FDCWD, filePath, buf, 512);
                   if (NULL != strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR)) {
                       LOGD("found frida by pipe");
                       closedir(dir);
                       return 0;
                   }
               }

           }


       }else{
           LOGD("can not open fd");
       }
       closedir(dir);
       return 0;
   }

static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = 0;
    char map[512];
    int counter = 0;

    if ((fd = openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        while ((read_one_line(fd, map, 512)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (strstr(map, libstocheck[i]) != NULL) {
                    char tmp[256] = "";
                    char path[256] = "";
                    char buf[5] = "";
                    sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                    LOGD("init array %s %s",buf,path);
                    if (buf[2] == 'x') {
                        size_t size = strlen(path) + 1;
                        filepaths[i] = malloc(size);
                        LOGD("%d",i);
                        strlcpy(filepaths[i], path, size);
                        LOGD("cnm %s",filepaths[i]);
                        counter++;
                    }
                }
            }
            LOGD("ssdfdg");
            if (counter == NUM_LIBS)
                break;
        }
        close(fd);
        LOGD("sfsdssgfrsdf");
    }

}


static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *) buffer;
    size_t i;
    for (i = 0; i < len; ++i)
        seed += (unsigned long) (*buf++);
    return seed;
}



static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {

    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd;
    int execSectionCount = 0;
    fd = openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return NULL;
    }

    read(fd, &ehdr, sizeof(Elf_Ehdr));
    lseek(fd, (off_t) ehdr.e_shoff, SEEK_SET);

    unsigned long long memsize[2] = {0};
    unsigned long long offset[2] = {0};


    for (int i = 0; i < ehdr.e_shnum; i++) {
        memset(&sectHdr, 0, sizeof(Elf_Shdr));
        read(fd, &sectHdr, sizeof(Elf_Shdr));

//        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

        //Typically PLT and Text Sections are executable sections which are protected
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
//            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

            offset[execSectionCount] = sectHdr.sh_offset;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) {
                break;
            }
        }
    }
        LOGD("dssdsfdsgfdhghgfd %d",execSectionCount);
    if (execSectionCount == 0) {
       LOGD("not exe ection found");
        close(fd);
        return false;
    }
    //This memory is not released as the checksum is checked in a thread
    *pTextSection = malloc(sizeof(execSection));

    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem = 0;
    for (int i = 0; i < execSectionCount; i++) {
        lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = malloc(memsize[i] * sizeof(uint8_t));
        read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i] = offset[i];
        (*pTextSection)->memsize[i] = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        LOGD("checksum finish");
        free(buffer);
//        __android_log_print(ANDROID_LOG_WARN, APPNAME, "ExecSection:[%d][%ld][%ld][%ld]", i,
//                            offset[i],
//                            memsize[i], (*pTextSection)->checksum[i]);
    }

    close(fd);
    LOGD("fssdggggggggggggggggggggggg");
    return true;
}



void prepare_to_check_sum(){
    char *filePaths[NUM_LIBS];

    parse_proc_maps_to_fetch_path(filePaths);

    for (int i = 0; i < NUM_LIBS; i++) {
        fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
        LOGD("finsh fetch %d",i);
        if (filePaths[i] != NULL)
            free(filePaths[i]);
    }
  LOGD("finish jni_onload");

   }


bool scan_executable_segments(char *map, execSection *pElfSectArr, const char *libraryName) {
    unsigned long start, end;
    char buf[256] = "";
    char path[512] = "";
    char tmp[100] = "";

    sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);
    //__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Map [%s]", map);

    if (buf[2] == 'x') {
        if (buf[0] == 'r') {
            uint8_t *buffer = NULL;

            buffer = (uint8_t *) start;
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                if (start + pElfSectArr->offset[i] + pElfSectArr->memsize[i] > end) {
                    if (pElfSectArr->startAddrinMem != 0) {
                        buffer = (uint8_t *) pElfSectArr->startAddrinMem;
                        pElfSectArr->startAddrinMem = 0;
                        break;
                    }
                }
            }
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                unsigned long output = checksum(buffer + pElfSectArr->offset[i],
                                                pElfSectArr->memsize[i]);
//                __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Checksum:[%ld][%ld]", output,
//                                    pElfSectArr->checksum[i]);

                if (output != pElfSectArr->checksum[i]) {
                   LOGD("find frida by check so");

                }
            }

        } else {

            char ch[10] = "", ch1[10] = "";
            __system_property_get("ro.build.version.release", ch);
            __system_property_get("ro.system.build.version.release", ch1);
            int version = atoi(ch);
            int version1 = atoi(ch1);
            if (version < 10 || version1 < 10) {
                LOGD("verion < 10");
            } else {
                if (0 == strncmp(libraryName, LIBC, strlen(LIBC))) {
                    //If it is not readable, then most likely it is not manipulated by Frida
                    LOGD("can not read libc");

                } else {
                    LOGD("another problem");
                }
            }
        }
        return true;
    } else {
        if (buf[0] == 'r') {
            pElfSectArr->startAddrinMem = start;
        }
    }
    return false;
}


   int check_frida_hook(){
       int fd = 0;
       char map[256];

       if ((fd = openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

           while ((read_one_line(fd, map, 256)) > 0) {
               for (int i = 0; i < NUM_LIBS; i++) {
                   if (strstr(map, libstocheck[i]) != NULL) {
                       if (true == scan_executable_segments(map, elfSectionArr[i], libstocheck[i])) {
                            close(fd);
                           return 1;
                           break;
                       }
                   }
               }
           }
       } else {


       }
       close(fd);
       return 0;
   }

JNIEXPORT jstring JNICALL
Java_com_s20000s_detector_MainActivity_AntiFrida(JNIEnv *env, jclass clazz) {

      //check_process_name();

    pthread_t t;
    prepare_to_check_sum();
    pthread_create(&t, NULL, check_frida_port, (void *)NULL);
   int ret = check_frida_maps();
   int ret1 = check_frida_thread();
   int ret2 = check_frida_pipe();
  int ret3 = check_frida_hook();
   if(ret1 || ret2 || ret || ret3)
        return  (*env)->NewStringUTF(env,"found ");
    else
    return  (*env)->NewStringUTF(env,"security");

}