#include <iostream>
#include<cassert>
#include <unistd.h>

#include "ble_sniffer_driver.h"

#define m_assert(expr, msg) assert(( (void)(msg), (expr) ))


int find_skdm_flag = 0;
int find_skds_flag = 0;
unsigned char skdm[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char skds[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

void printf_raw_data(int channel,unsigned char *data,int len){
    uint32_t AccessAddress = data[10]|(data[11]<<8)|(data[12]<<16)|(data[13]<<24);
    printf("Channel: %d, AccessAddress: 0x%x\n",channel,AccessAddress);
    for (int i=0;i<len;++i){
        printf("%x",data[i]);
    }
    std::cout<<std::endl;
}

void check_skd(int channel, unsigned char* data, int data_len)
{
    //enc_req
    if (data[15] == 0x17 && data[16] == 0x03 && data_len == 44){
        find_skdm_flag = 1;
        for (int i = 0; i < 8; i++){
            skdm[i] = data[34 - i];
        }
    }
    //enc_rsp
    if (data[15] == 0x0d && data[16] == 0x04 && data_len == 34){
        find_skds_flag = 1;
        for (int i = 0; i < 8; i++){
            skds[i] = data[24 - i];
        }
    }
    // Debug
    if(find_skds_flag&&find_skdm_flag)
        printf_raw_data(channel,data,data_len);
}

// Start current trace collection
bool startCurTr(){

}

// Stop current trace collection
bool stopCurTr(){

}

// Record the plaintext
bool recordPt(int num, FILE* fd){
    fwrite(skdm,1,8*sizeof(unsigned char),fd);
    fwrite(skds,1,8*sizeof(unsigned char),fd);
}

void get_raw_data_cb(int dev_index,int channel,unsigned char *data,int data_len){
    // Debug
    // printf_raw_data(channel,data,data_len);
    check_skd(channel,data,data_len);
}

bool collect(const char ptFileName[],int targetNum){
    FILE* ptFile=fopen(ptFileName,"wb");
    int collectedNum=0;
    //Start first trace collection
    startCurTr();
    // Then loop
    while(true){
        if(find_skdm_flag&&find_skds_flag){
            stopCurTr();
            find_skdm_flag=find_skds_flag=0;
            recordPt(++collectedNum,ptFile);
            if(collectedNum>=targetNum){
                break;
            }
            startCurTr();
        }else{
            continue;
        }
    }
}


int main() {
    // Collection configs
    const char* ptFileName="/home/itemqq/Desktop/data/plaintext";
    const int targetNum=10;


    // Open devices
    int ret=scan_dev(NULL), DevIndex=0;
    m_assert(ret>0,"scan_dev <= 0");
    ret=open_dev(DevIndex);
    m_assert(ret==3,"open_dev != 3");

    // Get data will work in new thread
    start_get_data(DevIndex,get_raw_data_cb);

    // Collection
    collect(ptFileName,targetNum);

    // Close device
    ret=close_dev(DevIndex);
    if(ret!=3){std::cout<<"Warning: Close devices failed!";}
    sleep(10);
    return 0;
}
