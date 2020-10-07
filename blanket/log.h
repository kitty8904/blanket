#pragma once
#include "includes.h"

template <typename... Args>
void log(PCCHAR format, Args... args)
{
	DbgPrint(format, args...);
}