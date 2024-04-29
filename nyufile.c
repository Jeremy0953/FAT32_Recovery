#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <openssl/sha.h>
// Boot Sector
#pragma pack(push,1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
    unsigned char  BS_OEMName[8];     // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
    unsigned char  BPB_NumFATs;       // Number of FATs
    unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
    unsigned char  BPB_Media;         // Media type
    unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
    unsigned short BPB_NumHeads;      // Number of heads in storage device
    unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;      // A flag for FAT
    unsigned short BPB_FSVer;         // The major and minor version number
    unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
    unsigned char  BPB_Reserved[12];  // Reserved
    unsigned char  BS_DrvNum;         // BIOS INT13h drive number
    unsigned char  BS_Reserved1;      // Not used
    unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
    unsigned int   BS_VolID;          // Volume serial number
    unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
    unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

// Directory entry
#pragma pack(push,1)
typedef struct DirEntry {
    unsigned char  DIR_Name[11];      // File name
    unsigned char  DIR_Attr;          // File attributes
    unsigned char  DIR_NTRes;         // Reserved
    unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
    unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;       // Created day
    unsigned short DIR_LstAccDate;    // Accessed day
    unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;       // Written day
    unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
    unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

#define SHA_DIGEST_LENGTH 20
#define MAX_EQUAL_NAME 20
typedef unsigned int* FAT32;

// global variables
BootEntry *boot = NULL;
FAT32 fat1 = NULL;
unsigned char *data_region = NULL;
unsigned char *root_dir = NULL;


void PrintUsage(){
    printf("Usage: ./nyufile disk <options>\n");
    printf("  %-22s Print the file system information.\n", "-i");
    printf("  %-22s List the root directory.\n", "-l");
    printf("  %-22s Recover a contiguous file.\n", "-r filename [-s sha1]");
    printf("  %-22s Recover a possibly non-contiguous file.\n", "-R filename -s sha1");
    exit(1);
}

void PrintFilesystemInfo(){
    printf("Number of FATs = %d\n", boot->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", boot->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", boot->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", boot->BPB_RsvdSecCnt);
    exit(1);
}



// 辅助函数：获取下一个簇号
int getNextCluster(FAT32 fats, int currentCluster) {
    //printf("currentCluster = %d\n", currentCluster);
    if (currentCluster < 2) return -1;  // 无效的簇号
    if (currentCluster >= 0x0FFFFFF8) return -1;  // 无效的簇号
    // for (size_t i = 0; i < 10; i++)
    // {
    //     printf("fats[%d] = %x\n", i, fats[i]);
    // }
    
    unsigned int entry = fats[currentCluster];
    // printf("entry = %d\n", entry);
    // printf("entry = %x\n", entry);
    return (entry >= 0x0FFFFFF8) ? -1 : entry;
}

// 辅助函数：计算簇的数据地址
char* getClusterAddress(int cluster, int bytesPerCluster) {
    if (cluster < 2) {
        return NULL;  // Return NULL or handle it as you see appropriate
    }
    return (char*)(data_region + (cluster - 2) * bytesPerCluster);
}

void TransName(const unsigned char* rawName, char* name) {
    // name.size>=13
    strncpy(name, (const char*)rawName, 11);
    name[12] = '\0';
    // 删除名称中的填充空格
    int i = 0;
    int j = 8;
    for (i = 0; i < 8 && name[i] != ' '; i++);
    for (j = 8; j < 11 && name[j] != ' '; j++);
    if (i < 8 && j == 8){
        name[i] = '\0';
    }
    if (i < 8 && j > 8) {
        name[i] = '.';
        /*
        for (int k = 0 ; k < j-8 ; k++) {
            name[i+k+1] = rawName[k+8];
        }*/
        strncpy(name + i + 1, rawName + 8, j-8);
        name[i+j-7] = '\0';
    }
    
    if (i == 8 && j == 8) {
        name[i] = '\0';
    }
    
    if (i == 8 && j > 8) {
        name[i] = '.';
        strncpy(name + i + 1, rawName + 8, j-8);
        name[j+1] = '\0';
    }
}

// 辅助函数：处理并打印目录项的名称
void printEntryName(const unsigned char* rawName, int isDirectory) {
    char name[13];
    TransName(rawName, name);
    if (isDirectory) {
        printf("%s/ ", name);
    } else {
        printf("%s ", name);
    }
}


void ListRootDirectory(DirEntry* rootDir) {
    // printf("Entering ListRootDirectory\n");
    int totalEntries = 0;
    int cluster = boot->BPB_RootClus;
    int bytesPerCluster = boot->BPB_SecPerClus * boot->BPB_BytsPerSec;
    //printf("Listing Root Directory:\n");
    //printf("Current cluster: %d\n", cluster);
    // printf("root = %p\n", rootDir);
    DirEntry* current = rootDir;
    int entriesPerCluster = bytesPerCluster / sizeof(DirEntry);
    while (cluster != -1) {
        // printf("current = %p\n", current);
        // printf("current = %p\n", current);
        for (int i = 0; i < entriesPerCluster; i++, current++) {
            // printf("current->DIR_Name[0] = %x\n", current->DIR_Name[0]);
            if (current->DIR_Name[0] == 0x00) break; // 检查目录条目是否结束
            if (current->DIR_Name[0] == 0xE5) continue; // 跳过已删除条目

            int startCluster = (current->DIR_FstClusHI << 16) | current->DIR_FstClusLO;
            printEntryName(current->DIR_Name, current->DIR_Attr & 0x10);
            
            if (current->DIR_Attr & 0x10) { // 是目录
                printf("(starting cluster = %d)\n", startCluster);
            } else { // 是文件
                printf("(size = %u", current->DIR_FileSize);
                if (current->DIR_FileSize > 0) {
                    printf(", starting cluster = %d", startCluster);
                }
                printf(")\n");
            }
            totalEntries++;
        }

        // 获取下一个簇
        if (current->DIR_Name[0] == 0x00) break;  // 如果目录结束，退出循环

        int nextCluster = getNextCluster(fat1, cluster);
        // printf("nextCluster = %d\n", nextCluster);
        if (nextCluster != -1 && nextCluster > 1) {
            cluster = nextCluster;
            current = (DirEntry*)getClusterAddress(cluster, bytesPerCluster);
            // printf("current = %p\n", current);
            if (!current) {
                fprintf(stderr, "Failed to access next cluster.\n");
                break;  // 如果地址无效，终止循环
            }
        } else {
            break;  // 没有更多簇或簇号无效
        }
    }

    printf("Total number of entries = %d\n", totalEntries);
}

void FindDeletedFile(char *filename, int *foundCount, DirEntry **deleted) {
    // printf("begin find deleted file\n");
    *foundCount = 0;  // 初始化找到的文件数量为0
    char name[13];
    int cluster = boot->BPB_RootClus;
    int bytesPerCluster = boot->BPB_SecPerClus * boot->BPB_BytsPerSec;
    DirEntry* current = (DirEntry*)root_dir;
    int entriesPerCluster = bytesPerCluster / sizeof(DirEntry);

    while (cluster != -1) {
        for (int i = 0; i < entriesPerCluster; i++, current++) {
            if (current->DIR_Name[0] == 0x00) break; // 检查目录条目是否结束
            if (current->DIR_Name[0] == 0xE5) { // 检查是否为已删除的文件
                TransName(current->DIR_Name, name);
                if (strcmp(name+1, filename+1) == 0) {
                    deleted[*foundCount] = current;
                    (*foundCount)++;
                }
            }
        }

        if (current->DIR_Name[0] == 0x00) break;  // 如果目录结束，退出循环

        int nextCluster = getNextCluster(fat1, cluster);
        if (nextCluster > 1 && nextCluster < 0x0FFFFFF8) {
            cluster = nextCluster;
            current = (DirEntry*)getClusterAddress(cluster, bytesPerCluster);
            if (!current) {
                fprintf(stderr, "Failed to access next cluster.\n");
                break;  // 如果地址无效，终止循环
            }
        } else {
            break;  // 没有更多簇或簇号无效
        }
    }
}


void SyncFAT(FAT32 *FATS){
    //sync after fat1 updated
    for (size_t i = 1; i < boot->BPB_NumFATs; i++)
    {
        memcpy(FATS[i], fat1, boot->BPB_FATSz32 * boot->BPB_BytsPerSec);
    }
}

void setFATEntry(int *fat, int cluster, int value) {
    fat[cluster] = value;  // Directly setting the value in the FAT
    // Depending on the system, you might need to flush this update to the disk manually.
}

void RecoverContiguousFile(char *filename, char *expectedSha1) {
    int count = 0;
    DirEntry **deleteds = (DirEntry **)malloc(MAX_EQUAL_NAME * sizeof(DirEntry *));
    FindDeletedFile(filename, &count, deleteds);
    if (count == 0) {
        printf("%s: file not found\n", filename);
        free(deleteds);
        return;
    }
    if (count > 1 && expectedSha1 == NULL) {
        printf("%s: multiple candidates found\n", filename);
        free(deleteds);
        return;
    }
    bool success = false;
    for (int i = 0; i < count; i++)
    {
        DirEntry *deleted = deleteds[0];
        int startCluster = (deleted->DIR_FstClusHI << 16) | deleted->DIR_FstClusLO;
        int fileSize = deleted->DIR_FileSize;
        int bytesPerCluster = boot->BPB_SecPerClus * boot->BPB_BytsPerSec;

        int totalClusters = (fileSize + bytesPerCluster - 1) / bytesPerCluster;
        char *fileData = (char *)malloc(fileSize);
        if (fileData == NULL) {
            fprintf(stderr, "Failed to allocate memory for file recovery.\n");
            free(deleteds);
            return;
        }
        int currentCluster = startCluster;
        char *currentPtr = fileData;
        int bytesRead = 0;
        for (int i = 0; i < totalClusters; i++) {
            char *clusterData = getClusterAddress(currentCluster, bytesPerCluster);
            if (clusterData == NULL) {
                fprintf(stderr, "Failed to access cluster %d.\n", currentCluster);
                free(fileData);
                free(deleteds);
                return;
            }
            int bytesToCopy = bytesPerCluster < fileSize - bytesRead ? bytesPerCluster : fileSize - bytesRead;
            // int bytesToCopy = min(bytesPerCluster, fileSize - bytesRead);
            memcpy(currentPtr, clusterData, bytesToCopy);
            currentPtr += bytesToCopy;
            bytesRead += bytesToCopy;

            // Update FAT table
            int nextCluster = (i == totalClusters - 1) ? 0x0FFFFFFF : currentCluster + 1;
            fat1[currentCluster] = nextCluster;
            currentCluster++;
        }
    
        // Check SHA-1 if provided
        if (expectedSha1 != NULL) {
            unsigned char md[SHA_DIGEST_LENGTH];
            SHA1((unsigned char*)fileData, fileSize, md);
            char actualSha1[SHA_DIGEST_LENGTH * 2 + 1];
            for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                sprintf(&actualSha1[i * 2], "%02x", md[i]);
            }
            // printf("Actual SHA-1: %s\n", actualSha1);
            // printf("Expected SHA-1: %s\n", expectedSha1);
            if (strcmp(actualSha1, expectedSha1) != 0) {
                free(fileData);
                continue;
            }
        }
        success = true;
        // Write data to file if SHA-1 matches or is not provided
        FILE *recoveredFile = fopen(filename, "wb");
        if (recoveredFile == NULL) {
            fprintf(stderr, "Failed to open file %s for writing.\n", filename);
            free(fileData);
            free(deleteds);
            return;
        }
        fwrite(fileData, 1, fileSize, recoveredFile);
        fclose(recoveredFile);
        free(fileData);
        free(deleteds);
        if (deleted->DIR_Name[0] == 0xE5) {
            deleted->DIR_Name[0] = filename[0];  
        }
        printf("%s: successfully recovered%s\n", filename, (expectedSha1 != NULL ? " with SHA-1" : ""));
    }
    if (!success) {
        printf("%s: file not found\n", filename);
        free(deleteds);
    }
}

void RecoverNonContiguousFile(char *filename){
    //TODO: Implement this function
    printf("Recover Non-Contiguous File\n");
}


int main(int argc, char* argv[]){
    int ch;
    char *filename = NULL;
    char *diskname = NULL;
    char *sha1 = NULL;
    bool i_flag = false, l_flag = false, r_flag = false, R_flag = false, s_flag = false;

    if (argc < 3) {
        PrintUsage();
    }
    diskname = argv[1];
    while ((ch = getopt(argc-1, argv+1, "ilr:R:s:")) != -1) {
        switch (ch) {
            case 'i':
                if (l_flag || r_flag || R_flag || s_flag || i_flag) {
                    PrintUsage();  // Ensures -i is not mixed with other flags
                }
                i_flag = true;
                break;
            case 'l':
                if (i_flag || r_flag || R_flag || s_flag || l_flag) {
                    PrintUsage(); // Ensures -l is not mixed with other flags
                }
                l_flag = true;
                break;
            case 'r':
                if (i_flag || l_flag || R_flag || r_flag) {
                    PrintUsage();
                }
                r_flag = true;
                filename = optarg;
                break;
            case 'R':
                if (i_flag || l_flag || r_flag || R_flag) {
                    PrintUsage();
                }
                R_flag = true;
                filename = optarg;
                break;
            case 's':
                if(s_flag) {
                    PrintUsage();  // Ensures -s is used only once
                }
                if (!r_flag && !R_flag) {
                    PrintUsage();  // Ensures -s is used only with -r or -R
                }
                s_flag = true;
                sha1 = optarg;
                break;
            default:
                PrintUsage();
        }
    }

    // Post processing to validate required combinations
    if (i_flag && (l_flag || r_flag || R_flag || s_flag)) {
        PrintUsage();  // Further ensure -i is used alone
    }

    if (l_flag && (i_flag || r_flag || R_flag || s_flag)) {
        PrintUsage();  // Further ensure -l is used alone
    }

    if ((r_flag || R_flag) && !filename) {
        PrintUsage();
    }

    if ((r_flag || R_flag) && s_flag && (sha1 == NULL || strlen(sha1) != 40)) {
        PrintUsage();
    }

    if (R_flag && !s_flag) {
        PrintUsage();
    }
    int fd = open(diskname, O_RDWR);
    struct stat sb;
    fstat(fd, &sb);
    unsigned char *mapped_addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    

    // get the system info

    // global variable
    boot = (BootEntry *)(mapped_addr);
    if (boot == NULL)
    {
        printf("Error: failed to map the disk image to memory.\n");
    }
    
    unsigned int fat_start_byte = boot->BPB_RsvdSecCnt * boot->BPB_BytsPerSec;
    //printf("fat_start_byte = %x\n", fat_start_byte);
    //printf("fat_num = %d\n", boot->BPB_NumFATs);
    //printf("fat_size = %d\n", boot->BPB_FATSz32 * boot->BPB_BytsPerSec);
    unsigned int **FATS = malloc(sizeof(unsigned int *) * boot->BPB_NumFATs);
    for (int i = 0; i < boot->BPB_NumFATs; i++) {
        FATS[i] = (unsigned int *)(mapped_addr + fat_start_byte + boot->BPB_FATSz32 * boot->BPB_BytsPerSec * i);
    }

    //global variable
    fat1 = FATS[0];
    // for (size_t i = 0; i < 20; i++)
    // {
    //    fat1[i] = FATS[0][i];
    //    printf("fat1[%d] = %x\n", i, fat1[i]);
    // }
    

    unsigned int data_region_start_byte = fat_start_byte + boot->BPB_FATSz32 * boot->BPB_BytsPerSec * boot->BPB_NumFATs;
    //global variable
    data_region = mapped_addr + data_region_start_byte;

    unsigned int root_dir_byte = data_region_start_byte + (boot->BPB_RootClus - 2) * boot->BPB_SecPerClus * boot->BPB_BytsPerSec;
    //global variable
    root_dir = mapped_addr + root_dir_byte;

    

    // Process the options
    if (i_flag) 
        PrintFilesystemInfo();
    if (l_flag) 
        ListRootDirectory((DirEntry *)root_dir);
    if (r_flag) 
        {
            // printf("Recover Contiguous File\n");
            RecoverContiguousFile(filename, sha1);
            SyncFAT(FATS);
        }
    if (R_flag)
        RecoverNonContiguousFile(filename);

    munmap(mapped_addr, sb.st_size);
    close(fd);
    free(FATS);
    return 0;
}