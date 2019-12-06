
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

# ifndef __UNICODECONV_H__
# define __UNICODECONV_H__

/*TBD: To write a suitable function which returns a meaningful string on passing the error values */

/* 

PRE:  Converts a Local string `localString' of length `localStringLen' to unicoded String `unicodeString'. The `unicodeString' is to be memory allocated before passing it to this function. The size of memory allocated is passed in `unicodeStringLen'.  

POST: Returns the length of the unicodedstring in case of successful conversion (err has value 0) and returns -1 in case of failure (err has a negative value). 

*/

int LocalToUnicode(char *localString,int localStringlen, char *unicodeString, int unicodeStringLen, int *err);

/* 

PRE:  Converts a unicoded string `unicodeString' of length `unicodeStringLen' to local String `localString'. The `localString' is to be memory allocated before passing it to this function. The size of memory allocated is passed in `localStringLen'. 

	NOTE: The localString is not NULL terminated. 

POST: Returns the length of the localstring in case of successful conversion (err has value 0) and returns -1 in case of failure (err has a negative value). 

*/

int UnicodeToLocal(char *unicodeString,int unicodeStringLen, char *localString, int localLen, int *err);

#endif
