noinst_PROGRAMS = vpncErrorHandlingGenerator
noinst_LTLIBRARIES = libErrorHandling.la

vpncErrorHandlingGenerator_SOURCES = vpncErrorHandlingGenerator.c 

libErrorHandling_la_SOURCES = \
			vpncErrorHandling.h \
			vpncErrorHandling.c \
			vpncErrorHandlingSupport.c

libErrorHandling_la_LDFLAGS = -version-info 1:0:0 -static

CLEAN_FILES = vpncErrorHandling.c

vpncErrorHandling.c: vpncErrorHandlingGenerator.c vpncErrorHandlingGenerator
	./vpncErrorHandlingGenerator


#AM_CPPFLAGS = `-DENABLE_NLS` 
