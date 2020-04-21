#define _CRT_SECURE_NO_WARNINGS 1

//	Main.cpp
//	Written by Team 9 

#include <windows.h>
#include <stdio.h>
#include <io.h>


// Global Variables
unsigned char gkey[65537];
unsigned char *gptrKey = gkey;			// used for inline assembly routines, need to access this way for Visual Studio
char gPassword[256] = "password";
unsigned char gPasswordHash[32];
unsigned char *gptrPasswordHash = gPasswordHash;	// used for inline assembly routines, need to access this way for Visual Studio

FILE *gfptrIn = NULL;
FILE *gfptrOut = NULL;
FILE *gfptrKey = NULL;
char gInFileName[256];
char gOutFileName[256];
char gKeyFileName[256];
int gOp = 0;			// 1 = encrypt, 2 = decrypt
int gNumRounds = 1;


// Prototypes
int sha256(char *fileName, char *dataBuffer, DWORD dataLength, unsigned char sha256sum[32]);



//////////////////////////////////////////////////////////////////////////////////////////////////
// code to encrypt the data as specified by the project assignment
void encryptData(char *data, int flength)
{
	__asm {
		//save registers
		push ebx
		push ecx
		push edx
		push esi
		push edi

		push ebp								// save ebp
		mov edi, data							// edi = data
		mov ecx, flength						// ecx = flength
		mov ebp, esp

		sub esp, 40
		mov [ebp-4], edi						// ebp-4 = *data
		mov [ebp-8], ecx						// ebp-8 = flength
		mov edi, gptrKey
		mov [ebp-12], edi						// ebp-12 = gptrKey
		mov edi, gptrPasswordHash
		mov [ebp-16], edi						// ebp-16 = gptrPasswordHash

		xor eax, eax

		mov [ebp-20], eax						// ebp-20 = currRound = 0
		mov [ebp-24], eax						// ebp-24 = x = 0
		mov [ebp-28], eax						// ebp-28 = index1 = 0
		mov [ebp-32], eax						// ebp-32 = hop_count1 = 0
		mov [ebp-36], eax						// ebp-36 = index2 = 0
		mov [ebp-40], eax						// ebp-40 = hop_count2 = 0


ROUNDLOOP:
		// The following instructions executes this line:
		// index1 = gPasswordHash[0+currRound*4] * 256 + gPasswordHash[1+currRound*4]
		mov esi, [ebp-16]						// esi = *gptrPasswordHash
		mov eax, [ebp-20]						// eax = currRound
		sal eax, 2								// eax = currRound * 4
		add esi, eax							// [esi] = gPasswordHash[0+currRound*4]
		movzx edx, byte ptr [esi]				// edx = [esi]
		sal edx, 8								// edx = gPasswordHash[0+currRound*4] * 256
		add esi, 1								// [esi] = gPasswordHash[1+currRound*4]
		movzx eax, byte ptr [esi]				// eax = gPasswordHash[1+currRound*4]
		add eax, edx							// eax = gPasswordHash[0+currRound*4] * 256 + gPasswordHash[1+currRound*4]
		mov [ebp-28], eax						// index1 = eax
		
		// The following instructions executes this line:
		// hop_count1 = gPasswordHash[2+currRound*4] * 256 + gPasswordHash[3+currRound*4]
		// if(hop_count1 == 0) hop_count1 = 0xFFFF
		add esi, 1								// [esi] = gPasswordHash[2+currRound*4]
		movzx edx, byte ptr [esi]				// edx = gPasswordHash[2+currRound*4]
		sal edx, 8								// edx = gPasswordHash[2+currRound*4] * 256
		add esi, 1								// [esi] = gPasswordHash[3+currRound*4]
		movzx eax, byte ptr [esi]				// eax = gPasswordHash[3+currRound*4]
		add eax, edx							// eax = gPasswordHash[2+currRound*4] * 256 + gPasswordHash[3+currRound*4]
		mov [ebp-32], eax						// hop_count1 = eax
		jnz HOP1NOTZERO
		mov [ebp-32], 0xFFFF					// if(hop_count1 == 0) hop_count1 = 0xFFFF

HOP1NOTZERO:

		// The following instructions executes this line:
		// index2 = gPasswordHash[4+round*4] * 256 + gPasswordHash[5+round*4]
		add esi, 1								// [esi] = gPasswordHash[4+currRound*4]
		movzx edx, byte ptr[esi]				// edx = gPasswordHash[4+currRound*4]
		sal edx, 8								// edx = gPasswordHash[4+currRound*4] * 256
		add esi, 1								// [esi] = gPasswordHash[5+currRound*4]
		movzx eax, byte ptr[esi]				// eax = gPasswordHash[5+currRound*4]
		add eax, edx							// eax = gPasswordHash[4+currRound*4] * 256 + gPasswordHash[5+currRound*4]
		mov [ebp-36], eax						// index2 = eax
		
		// The following instructions executes this line:
		// hop_count2 = gPasswordHash[6+round*4] * 256 + gPasswordHash[7+round*4]
		// if(hop_count2 == 0) hop_count2 = 0xFFFF
		add esi, 1								// [esi] = gPasswordHash[6+currRound*4]
		movzx edx, byte ptr[esi]				// edx = gPasswordHash[6+currRound*4]
		sal edx, 8								// edx = gPasswordHash[6+currRound*4] * 256
		add esi, 1								// [esi] = gPasswordHash[7+currRound*4]
		movzx eax, byte ptr[esi]				// eax = gPasswordHash[7+currRound*4]
		add eax, edx							// eax = gPasswordHash[6+currRound*4] * 256 + gPasswordHash[7+currRound*4]
		mov [ebp-40], eax						// hop_count2 = eax
		jnz HOP2NOTZERO
		mov [ebp-40], 0xFFFF					// if(hop_count1 == 0) hop_count1 = 0xFFFF

HOP2NOTZERO:
		

		xor eax, eax
		mov[ebp - 24], eax						// set x = 0 before loop
		mov edi, [ebp-4]						// edi = *data = file[x]
XLOOP:
		// The following instructions executes this line:
		// file[x] = file[x] ^ keyfile[index1];	
		mov esi, [ebp-12]						// esi = gptrKey = keyfile[]
		add esi, [ebp-28]						// [esi] = keyfile[index1] 
		movzx eax, byte ptr[esi]				// eax = [esi]	
		xor [edi], eax							// file[x] = file[x] ^ keyfile[index1]

		// The following instructions executes this line:
		// index1 += hop_count1;
		// if (index1 ≥ 65537) index1 -= 65537;
		mov eax, [ebp-32]						// eax = hop_count1
		mov edx, [ebp-28]						// edx = index1
		add edx, eax							// edx += hop_count1
		cmp edx, 0x10001						// if (edx ≥ 65537) edx -= 65537
		jl INDX1OKAY
		sub edx, 0x10001					 

INDX1OKAY:
		mov [ebp-28], edx						// index1 = edx

		
		/***** bit manipulations *****/
		
		mov al, byte ptr[edi]					// al = [edi]

		// 1. rotate 1 bit to right
		ror al, 1								

		// 2. swap nibbles
		ror al, 4								
							
		// 3. reverse bit order
		xor ecx, ecx
		xor ebx, ebx
		mov cx, 8
REVLOOP:
		rcr al, 1
		rcl bl, 1								// reversed byte goes into bl
		loop REVLOOP
		
		mov al, bl								// al = reversed byte

		
		// 4. swap half nibbles
		mov bl, al
		and al, 0x0F							// al has bottom nibble
		and bl, 0xF0							// bl has top nibble

		mov cl, al								// use cl as a temp during bottom swap

		and al, 0x0C							// al has top 2 bits of nibble
		shr al, 2								// shift them to the right

		and cl, 0x03							// cl has bottom 2 bits of nibble
		shl cl, 2								// shift them to the left

		or al, cl								// combine al and cl, half nibble for bottom has been swapped

		mov cl, bl								// use cl as a temp during top swap

		and bl, 0xC0							// bl has top 2 bits of nibble
		shr bl, 2								// shift them to the right

		and cl, 0x30							// cl has bottom 2 bits of nibble
		shl cl, 2								// shift them to the left

		or bl, cl								// combine bl and cl, half nibble for top has been swapped

		or al, bl								// combine the two nibbles


		// 5. rotate 1 bit to left
		rol al, 1								

		mov[edi], al

		/***** END bit manipulations *****/


		// The following instructions executes this line:
		// file[x] = file[x] ^ keyfile[index2];	
		mov esi, [ebp-12]						// esi = gptrKey = keyfile[]
		add esi, [ebp-36]						// [esi] = keyfile[index2] 
		movzx eax, byte ptr[esi]				// eax = [esi]	
		xor [edi], eax							// file[x] = file[x] ^ keyfile[index2]


		// The following instructions executes this line:
		// index2 += hop_count2;
		// if (index2 ≥ 65537) index2 -= 65537;
		mov eax, [ebp-40]						// eax = hop_count2
		mov edx, [ebp-36]						// edx = index2
		add edx, eax							// edx += hop_count2
		cmp edx, 0x10001						// if (edx ≥ 65537) edx -= 65537
		jl INDX2OKAY
		sub edx, 0x10001

INDX2OKAY:
		mov [ebp-36], edx						// index2 = edx

	
		// check x loop condition
		add edi, 1								// increment file[x]
		add [ebp-24], 1							// increment x
		mov eax, [ebp-24]
		mov ecx, [ebp-8]
		cmp eax, ecx
		jl XLOOP
// END XLOOP
		

		// check round loop condition
		add [ebp-20], 1							// increment currRound			
		mov eax, [ebp-20]
		cmp eax, gNumRounds
		jl ROUNDLOOP
// END ROUNDLOOP

		// reset stack before return
		mov esp, ebp
		pop ebp

		// restore registers
		pop edi
		pop esi
		pop edx
		pop ecx
		pop ebx
	}
	
	return;
} // encryptData


// code to read the file to encrypt
int encryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if(filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *) malloc(filesize);
	if(buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	encryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // encryptFile


//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
void decryptData(char *data, int flength)
{
	__asm {
			//save registers
			push ebx
			push ecx
			push edx
			push esi
			push edi

			push ebp								// save ebp
			mov edi, data							// edi = data
			mov ecx, flength						// ecx = flength
			mov ebp, esp

			sub esp, 40
			mov [ebp-4], edi						// ebp-4 = *data
			mov [ebp-8], ecx						// ebp-8 = flength
			mov edi, gptrKey
			mov [ebp-12], edi						// ebp-12 = gptrKey
			mov edi, gptrPasswordHash
			mov [ebp-16], edi						// ebp-16 = gptrPasswordHash

			
			mov eax, gNumRounds
			mov [ebp-20], eax						// ebp-20 = currRound = gNumRounds

			xor eax, eax
			mov [ebp-24], eax						// ebp-24 = x = 0
			mov [ebp-28], eax						// ebp-28 = index1 = 0
			mov [ebp-32], eax						// ebp-32 = hop_count1 = 0
			mov [ebp-36], eax						// ebp-36 = index2 = 0
			mov [ebp-40], eax						// ebp-40 = hop_count2 = 0

			//decrypt uses a descending round loop
ROUNDLOOP :
			// The following instructions executes this line:
			// index1 = gPasswordHash[0+currRound*4] * 256 + gPasswordHash[1+currRound*4]
			mov esi, [ebp-16]						// esi = *gptrPasswordHash
			mov eax, [ebp-20]						// eax = currRound
			sub eax, 1								// eax = (currRound - 1) because of descending loop
			sal eax, 2								// eax = currRound * 4
			add esi, eax							// [esi] = gPasswordHash[0+currRound*4]
			movzx edx, byte ptr [esi]				// edx = [esi]
			sal edx, 8								// edx = gPasswordHash[0+currRound*4] * 256
			add esi, 1								// [esi] = gPasswordHash[1+currRound*4]
			movzx eax, byte ptr [esi]				// eax = gPasswordHash[1+currRound*4]
			add eax, edx							// eax = gPasswordHash[0+currRound*4] * 256 + gPasswordHash[1+currRound*4]
			mov [ebp-28], eax						// index1 = eax

			// The following instructions executes this line:
			// hop_count1 = gPasswordHash[2+currRound*4] * 256 + gPasswordHash[3+currRound*4]
			// if(hop_count1 == 0) hop_count1 = 0xFFFF
			add esi, 1								// [esi] = gPasswordHash[2+currRound*4]
			movzx edx, byte ptr [esi]				// edx = gPasswordHash[2+currRound*4]
			sal edx, 8								// edx = gPasswordHash[2+currRound*4] * 256
			add esi, 1								// [esi] = gPasswordHash[3+currRound*4]
			movzx eax, byte ptr [esi]				// eax = gPasswordHash[3+currRound*4]
			add eax, edx							// eax = gPasswordHash[2+currRound*4] * 256 + gPasswordHash[3+currRound*4]
			mov [ebp-32], eax						// hop_count1 = eax
			jnz HOP1NOTZERO
			mov [ebp-32], 0xFFFF					// if(hop_count1 == 0) hop_count1 = 0xFFFF

HOP1NOTZERO:

			// The following instructions executes this line:
			// index2 = gPasswordHash[4+round*4] * 256 + gPasswordHash[5+round*4]
			add esi, 1								// [esi] = gPasswordHash[4+currRound*4]
			movzx edx, byte ptr [esi]				// edx = gPasswordHash[4+currRound*4]
			sal edx, 8								// edx = gPasswordHash[4+currRound*4] * 256
			add esi, 1								// [esi] = gPasswordHash[5+currRound*4]
			movzx eax, byte ptr [esi]				// eax = gPasswordHash[5+currRound*4]
			add eax, edx							// eax = gPasswordHash[4+currRound*4] * 256 + gPasswordHash[5+currRound*4]
			mov [ebp-36], eax						// index2 = eax

			// The following instructions executes this line:
			// hop_count2 = gPasswordHash[6+round*4] * 256 + gPasswordHash[7+round*4]
			// if(hop_count2 == 0) hop_count2 = 0xFFFF
			add esi, 1								// [esi] = gPasswordHash[6+currRound*4]
			movzx edx, byte ptr [esi]				// edx = gPasswordHash[6+currRound*4]
			sal edx, 8								// edx = gPasswordHash[6+currRound*4] * 256
			add esi, 1								// [esi] = gPasswordHash[7+currRound*4]
			movzx eax, byte ptr [esi]				// eax = gPasswordHash[7+currRound*4]
			add eax, edx							// eax = gPasswordHash[6+currRound*4] * 256 + gPasswordHash[7+currRound*4]
			mov [ebp-40], eax						// hop_count2 = eax
			jnz HOP2NOTZERO
			mov [ebp-40], 0xFFFF					// if(hop_count2 == 0) hop_count2 = 0xFFFF

HOP2NOTZERO:


			xor eax, eax
			mov [ebp-24], eax						// set x = 0 before loop
			mov edi, [ebp-4]						// edi = *data = file[x]
XLOOP :
			// The following instructions executes this line:
			// file[x] = file[x] ^ keyfile[index2];	
			mov esi, [ebp-12]						// esi = gptrKey = keyfile[]
			add esi, [ebp-36]						// [esi] = keyfile[index2] 
			movzx eax, byte ptr [esi]				// eax = [esi]	
			xor [edi], eax							// file[x] = file[x] ^ keyfile[index2]

			// The following instructions executes this line:
			// index2 += hop_count2;
			// if (index2 ≥ 65537) index2 -= 65537;
			mov eax, [ebp-40]						// eax = hop_count2
			mov edx, [ebp-36]						// edx = index2
			add edx, eax							// edx += hop_count2
			cmp edx, 0x10001						// if (edx ≥ 65537) edx -= 65537
			jl INDX2OKAY
			sub edx, 0x10001

INDX2OKAY:
			mov [ebp-36], edx						// index2 = edx


			/***** bit manipulations *****/

			mov al, byte ptr [edi]					// al = [edi]

			// 1. rotate 1 bit to right
			ror al, 1

			// 2. swap half nibbles
			mov bl, al
			and al, 0x0F							// al has bottom nibble
			and bl, 0xF0							// bl has top nibble

			mov cl, al								// use cl as a temp during bottom swap

			and al, 0x0C							// al has top 2 bits of nibble
			shr al, 2								// shift them to the right

			and cl, 0x03							// cl has bottom 2 bits of nibble
			shl cl, 2								// shift them to the left

			or al, cl								// combine al and cl, half nibble for bottom has been swapped

			mov cl, bl								// use cl as a temp during top swap

			and bl, 0xC0							// bl has top 2 bits of nibble
			shr bl, 2								// shift them to the right

			and cl, 0x30							// cl has bottom 2 bits of nibble
			shl cl, 2								// shift them to the left

			or bl, cl								// combine bl and cl, half nibble for top has been swapped

			or al, bl								// combine the two nibbles


			// 3. reverse bit order
			xor ecx, ecx
			xor ebx, ebx
			mov cx, 8
		REVLOOP:
			rcr al, 1
			rcl bl, 1								// reversed byte goes into bl
			loop REVLOOP

			mov al, bl								// al = reversed byte

			// 4. swap nibbles
			ror al, 4

			// 5. rotate 1 bit to left
			rol al, 1

			mov [edi], al

			/***** END bit manipulations *****/


			// The following instructions executes this line:
			// file[x] = file[x] ^ keyfile[index1];	
			mov esi, [ebp-12]						// esi = gptrKey = keyfile[]
			add esi, [ebp-28]						// [esi] = keyfile[index1] 
			movzx eax, byte ptr [esi]				// eax = [esi]	
			xor [edi], eax							// file[x] = file[x] ^ keyfile[index1]

			// The following instructions executes this line:
			// index1 += hop_count1;
			// if (index1 ≥ 65537) index1 -= 65537;
			mov eax, [ebp-32]						// eax = hop_count1
			mov edx, [ebp-28]						// edx = index1
			add edx, eax							// edx += hop_count1
			cmp edx, 0x10001						// if (edx ≥ 65537) edx -= 65537
			jl INDX1OKAY
			sub edx, 0x10001

INDX1OKAY:
			mov [ebp-28], edx						// index1 = edx


			// check x loop condition
			add edi, 1								// increment file[x]
			add [ebp-24], 1							// increment x
			mov eax, [ebp-24]
			mov ecx, [ebp-8]
			cmp eax, ecx
			jl XLOOP
// END XLOOP


			// check round loop condition
			sub [ebp-20], 1							// decrement currRound			
			mov eax, [ebp-20]
			cmp eax, 0
			jg ROUNDLOOP
// END ROUNDLOOP


			// reset stack before return
			mov esp, ebp
			pop ebp

			// restore registers
			pop edi
			pop esi
			pop edx
			pop ecx
			pop ebx
	}

	return;
} // decryptData


// code to read in file and prepare for decryption
int decryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if(filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *) malloc(filesize);
	if(buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	decryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // decryptFile


//////////////////////////////////////////////////////////////////////////////////////////////////
FILE *openInputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "rb");
	if(fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open input file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openInputFile


FILE *openOutputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "wb+");
	if(fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open output file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openOutputFile


void usage(char *argv[])	//   cryptor.exe -e -i <input file> �k <keyfile> -p <password> [�r <#rounds>]
{
	printf("\n\nUsage:\n\n");
	printf("%s -<e=encrypt or d=decrypt> -i <message_filename> -k <keyfile> -p <password> [-r <#rounds>]\n\n", argv[0]);
	printf("-e				:encrypt the specified file\n");
	printf("-d				:decrypt the specified file\n");
	printf("-i filename		:the name of the file to encrypt or decrypt\n");
	printf("-p password		:the password to be used for encryption [default='password']\n");
	printf("-r <#rounds>	:number of encryption rounds (1 - 3)  [default = 1]\n");
	printf("-o filename		:name of the output file [default='encrypted.txt' or 'decrypted.txt'\n\n");
	exit(0);
} // usage


void parseCommandLine(int argc, char *argv[])
{
	int cnt;
	char ch;
	bool i_flag, o_flag, k_flag, p_flag, err_flag;

	i_flag = k_flag = false;				// these must be true in order to exit this function
	err_flag = p_flag = o_flag = false;		// these will generate different actions

	cnt = 1;	// skip program name
	while(cnt < argc)
	{
		ch = *argv[cnt];
		if(ch != '-')
		{
			fprintf(stderr, "All options must be preceeded by a dash '-'\n\n");
			usage(argv);
		}

		ch = *(argv[cnt]+1);
		if(0)
		{
		}

		else if(ch == 'e' || ch == 'E')
		{
			if(gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 1;	// encrypt
		}

		else if(ch == 'd' || ch == 'D')
		{
			if(gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 2;	// decrypt
		}

		else if(ch == 'i' || ch == 'I')
		{
			if(i_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an input file.\n\n");
				usage(argv);
			}
			i_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-i'\n\n");
				usage(argv);
			}
			strncpy(gInFileName, argv[cnt], 256);
		}

		else if(ch == 'o' || ch == 'O')
		{
			if(o_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an output file.\n\n");
				usage(argv);
			}
			o_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-o'\n\n");
				usage(argv);
			}
			strncpy(gOutFileName, argv[cnt], 256);
		}

		else if(ch == 'k' || ch == 'K')
		{
			if(k_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a key file.\n\n");
				usage(argv);
			}
			k_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-k'\n\n");
				usage(argv);
			}
			strncpy(gKeyFileName, argv[cnt], 256);
		}

		else if(ch == 'p' || ch == 'P')
		{
			if(p_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a password.\n\n");
				usage(argv);
			}
			p_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter a password after '-p'\n\n");
				usage(argv);
			}
			strncpy(gPassword, argv[cnt], 256);
		}

		else if(ch == 'r' || ch == 'R')
		{
			int x;

			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter number between 1 and 3 after '-r'\n\n");
				usage(argv);
			}
			x = atoi(argv[cnt]);
			if(x < 1 || x > 3)
			{
				fprintf(stderr, "Warning! Entered bad value for number of rounds. Setting it to one.\n\n");
				x = 1;
			}
			gNumRounds = x;
		}

		else
		{
			fprintf(stderr, "Error! Illegal option in argument. %s\n\n", argv[cnt]);
			usage(argv);
		}

		cnt++;
	} // end while

	if(gOp == 0)
	{
		fprintf(stderr, "Error! Encrypt or Decrypt must be specified.\n\n)");
		err_flag = true;
	}

	if(i_flag == false)
	{
		fprintf(stderr, "Error! No input file specified.\n\n");
		err_flag = true;
	}

	if(k_flag == false)
	{
		fprintf(stderr, "Error! No key file specified.\n\n");
		err_flag = true;
	}

	if(p_flag == false)
	{
		fprintf(stderr, "Warning! Using default 'password'.\n\n");
	}

	if(o_flag == false && err_flag == false)	// no need to do this if we have errors
	{
		strcpy(gOutFileName, gInFileName);
		if(gOp == 1)	// encrypt
		{
			strcat(gOutFileName, ".enc");
		}
		if(gOp == 2)	// decrypt
		{
			strcat(gOutFileName, ".dec");
		}
	}

	if(err_flag)
	{
		usage(argv);
	}
	return;
} // parseCommandLine






void main(int argc, char *argv[])
{
	int length, resulti;

	// parse command line parameters
	parseCommandLine(argc, argv);		// sets global variables, checks input options for errors

	// open the input and output files
	gfptrIn = openInputFile(gInFileName);
	gfptrKey = openInputFile(gKeyFileName);
	gfptrOut = openOutputFile(gOutFileName);

	length = (size_t) strlen(gPassword);

	resulti = sha256(NULL, gPassword, length, gPasswordHash);		// get sha-256 hash of password
	if(resulti != 0)
	{
		fprintf(stderr, "Error! Password not hashed correctly.\n\n");
		exit(-1);
	}

	length = fread(gkey, 1, 65537, gfptrKey);
	if(length != 65537)
	{
		fprintf(stderr, "Error! Length of key file is not at least 65537.\n\n");
		exit(-1);
	}
	fclose(gfptrKey);
	gfptrKey = NULL;

	if(gOp == 1)	// encrypt
	{
		encryptFile(gfptrIn, gfptrOut);
	}
	else
	{
		decryptFile(gfptrIn, gfptrOut);
	}

	fclose(gfptrIn);
	fclose(gfptrOut);
	return;
} // main
