// FPGA_Spoof.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "FPGA_Spoof/FPGA_Spoof.h"

int main()
{
	if (FPGA_Spoof::InitFPGA())
	{
		FPGA_Spoof::SpoofFPGA();

	}
	system("pause");
	return 0;
}
