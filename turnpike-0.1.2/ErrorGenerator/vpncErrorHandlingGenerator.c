
/************************************************************************************
*   Copyright (c) 2005, Novell Inc.,                                                * 
*   All rights reserved.                                                            *
*                                                                                   *
*   Redistribution and use in source and binary forms, with or without              *
*   modification, are permitted provided that the following conditions              *
*   are met:                                                                        *
*   1.  Redistributions of source code must retain the above copyright              *
*       notice, this list of conditions and the following disclaimer.               *
*   2.  Redistributions in binary form must reproduce the above copyright           *
*       notice, this list of conditions and the following disclaimer in the         *
*       documentation and/or other materials provided with the distribution.        *
*   3.  Neither the name of the Novell nor the names of its contributors            *
*       may be used to endorse or promote products derived from this software       *
*       without specific prior written permission.                                  *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND *
*   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           *
*   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE      *
*   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE *
*   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
*   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS         *
*   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)           *
*   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT      *
*   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY       *
*   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF          *
*   SUCH DAMAGE.                                                                    *
*************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
int main()
{
	FILE *readFile, *writeFile;
	char errorCode[31], errorString[1024];

	if(readFile = fopen("vpncErrorStrings.txt", "r"), readFile == NULL) {
		perror("can not open the file\n");
		exit(0);
	}
	if(writeFile = fopen("vpncErrorHandling.c", "w+"), writeFile == NULL) {
		perror("can not open the file\n");
		exit(0);
	}	
//	fprintf(writeFile, "#include<stdio.h>\n#include<stdlib.h>\n#include \"vpncError.h\"\n");
	fprintf(writeFile, "#include<stdio.h>\n#include<stdlib.h>\n");
	fprintf(writeFile," \n \
			#ifdef ENABLE_NLS\n \
			#  include <libintl.h>\n \
			#  undef _ \n \
			#  define _(String) dgettext (PACKAGE, String) \n \
			#  ifdef gettext_noop \n \
			#    define N_(String) gettext_noop (String) \n \
			#  else \n \
			#    define N_(String) (String) \n \
			#  endif \n \
			#else \n \
			#  define textdomain(String) (String) \n \
			#  define gettext(String) (String) \n \
			#  define dgettext(Domain,Message) (Message) \n \
			#  define dcgettext(Domain,Message,Type) (Message)\n \
			#  define bindtextdomain(Domain,Directory) (Domain)\n \
			#  define _(String) (String)\n \
			#  define N_(String) (String)\n \
			#endif\n \
			\
			#define PACKAGE \"turnpike\" \n  \
			");

	fprintf(writeFile, "\n char * _errString(int errorNo)\n { \n");
	fprintf(writeFile, "\t switch(errorNo) {\n");

	while(	fscanf(readFile, "%s %[^\n]", errorCode, errorString)!=EOF){
		fprintf(writeFile, "\t\tcase %s: \n", errorCode);
		fprintf(writeFile, "\t\t\treturn _(\"%s\");\n", errorString);

	}

	fprintf(writeFile, "\t\tdefault : \n\t\t\treturn (\"%s\");\n", "no error code is matched");
	fprintf(writeFile, "\t}\n}\n");

	fclose(writeFile);
	fclose(readFile);
	return 0;
}
