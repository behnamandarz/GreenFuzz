// This code is GPLed by Yan Shoshitaishvili

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>


#include<sys/time.h> // zyp for logging time

int preeny_debug_on = 1;
int preeny_info_on = 1;
int preeny_error_on = 1;


struct timeval t;

void preeny_debug(char *fmt, ...)
{
	if (!preeny_debug_on) return;

	gettimeofday(&t, NULL);  //zyp
	printf("+++ [%ld:%06ld] ", t.tv_sec, t.tv_usec);
	va_list args;
	va_start(args,fmt);
	vprintf(fmt,args);
	va_end(args);

	fflush(stdout);
}

void preeny_info(char *fmt, ...)
{
	if (!preeny_info_on) return;

	gettimeofday(&t, NULL);  //zyp
	printf("--- [%ld:%06ld] ", t.tv_sec, t.tv_usec);
	va_list args;
	va_start(args,fmt);
	vprintf(fmt,args);
	va_end(args);

	fflush(stdout);
}

void preeny_error(char *fmt, ...)
{
	if (!preeny_error_on) return;

	fprintf(stderr, "!!! ERROR: ");
	va_list args;
	va_start(args,fmt);
	vfprintf(stderr, fmt,args);
	va_end(args);

	fflush(stderr);
}

__attribute__((constructor)) void preeny_logging_init()
{
	preeny_debug_on = preeny_debug_on || (getenv("PREENY_DEBUG") && (strcmp(getenv("PREENY_DEBUG"), "1") == 0));
	preeny_info_on = preeny_info_on || (getenv("PREENY_INFO") && (strcmp(getenv("PREENY_INFO"), "1") == 0));
	preeny_error_on = preeny_error_on || (getenv("PREENY_ERROR") && (strcmp(getenv("PREENY_ERROR"), "1") == 0));
}