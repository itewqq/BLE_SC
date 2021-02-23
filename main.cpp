#include <iostream>
#include<cassert>
#include <unistd.h>

#include "ble_sniffer_driver.h"

#define m_assert(expr, msg) assert(( (void)(msg), (expr) ))

void printf_raw_data(int channel,unsigned char *data,int len){
    uint32_t AccessAddress = data[10]|(data[11]<<8)|(data[12]<<16)|(data[13]<<24);
    std::cout<<"Channel: "<<channel<<"  "<<AccessAddress<<std::endl;
    for (int i=0;i<len;++i){
        printf("%x",data[i]);
    }
    std::cout<<std::endl;
}

void get_raw_data_cb(int dev_index,int channel,unsigned char *data,int data_len){
    printf_raw_data(channel,data,data_len);
}

int main() {
    // Open devices
    int ret=scan_dev(NULL), DevIndex=0;
    m_assert(ret>0,"scan_dev <= 0");
    ret=open_dev(DevIndex);
    m_assert(ret==3,"open_dev != 3");

    // Get data will work in new thread
    start_get_data(DevIndex,get_raw_data_cb);
    sleep(10);

    // Close device
    ret=close_dev(DevIndex);
    if(ret!=3){std::cout<<"Warning: Close devices failed!";}
    sleep(10);
    return 0;
}
