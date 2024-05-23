#include <stdio.h>

#include "util.h"
#include "pcapReader.h"

int main() {
    // read pcap
    struct pcap_reader* reader = initPcapReader("captured_6.pcap");
    // read pcap file
    while (next_packet(reader)) {}

    // read log
    // 打开文件
    FILE *filePointer = fopen("rec_nic_timer_6_replay.log", "r"); // "r" 模式表示以只读方式打开文件

    // 检查文件是否成功打开
    if (filePointer == NULL) {
        printf("文件打开失败。\n");
        return 1; // 返回非0值表示程序异常终止
    } else {
        printf("文件成功打开，准备读取。\n");
        // 在这里进行文件读取操作
        unsigned long long first_n4;
        unsigned long long n0, n1, n2, n3, n4, n5;
        int count = 0;
        while (fscanf(filePointer, "%llu\t%llu\t%llu\t%llu\t%llu\t%llu", &n0, &n1, &n2, &n3, &n4, &n5) == 6) {
            // 处理每行数据，这里简单地打印出来
            // printf("%llu\t%llu\t%llu\t%llu\t%llu\t%llu\n", n0, n1, n2, n3, n4, n5);
            if (count == 0) first_n4 = n4;
            uint64_t x = n4 - first_n4;
            uint64_t y = reader->packets[count].timestamp - reader->packets[0].timestamp;
            uint64_t diff = x > y ? x - y : y - x;
            printf("%llu\n", (unsigned long long)diff);
            count++;
            if (count >= reader->packet_count) break;
        }

        // 完成读取后，关闭文件
        fclose(filePointer);
    }


    return 0;
}