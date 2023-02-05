#include"ValidMemoryEnum.hpp"
#include<iostream>
using std::cout;
using std::endl;
using std::hex;
int main() 
{
	ValidMemoryEnum::GetInstance(GetCurrentProcessId());
	Sleep(1000);
	for (const auto&[addr,size]: ValidMemoryEnum::GetInstance(GetCurrentProcessId()).m_InvalidHeapTable)
	{
		cout << "HeapStarAddr 0x" << hex << addr << " size " << size << endl;
	} 
	for (const auto&[addr,size]: ValidMemoryEnum::GetInstance(GetCurrentProcessId()).m_InvalidStackTable)
	{
		cout << "StackStarAddr 0x" << hex << addr << " size " << size << endl;
	} 
	
}