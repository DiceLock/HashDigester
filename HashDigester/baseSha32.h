//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.3.0.0.1
//
// Copyright © 2009-2010 DiceLock Security, LLC. All rights reserved.
//
//                               DISCLAIMER
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef BASESHA32_HPP

#define BASESHA32_HPP

#ifdef DICELOCKCIPHER_EXPORTS
   #define CLASS_DECLSPEC    __declspec(dllexport)
#else
   #define CLASS_DECLSPEC    __declspec(dllimport)
#endif

#include "baseHash.h"


#define BASESHA_32_Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define BASESHA_32_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define BASESHA_32_DATABITS   512    // 512 block bits
#define BASESHA_32_DATAUCHARS 64     // 64  block unsigned chars
#define BASESHA_32_DATAULONGS 16     // 16  block unsigned longs

#define BASESHA_32_EQUATIONMODULO  448


namespace DiceLockSecurity {

  namespace Hash {

	class BaseSha32 abstract : public BaseHash {

		protected:

			// Number of data bits to compute hash
			static const unsigned short int dataHashBits;
			// Number of data unsigned chars to compute hash
			static const unsigned short int dataHashUCs;
			// Number of data unsigned long integers to compute hash
			static const unsigned short int dataHashULs;

			// Equation modulo constant value
			static const unsigned short int equationModulo;

			// Array to store remaining bytes of intermediate hash operation
			unsigned char remainingBytes[BASESHA_32_DATAUCHARS];
			unsigned long int remainingBytesLength;

			// Total processed message length in bytes
			unsigned long int messageBitLengthHigh;
			unsigned long int messageBitLengthLow;

			// Gets the number of unsigned chars in the hash block to be hashed
			CLASS_DECLSPEC unsigned short int GetDataHashUCs(void);

			// Adds messaage length processed, if it is greater than unsigned long makes use
			// of another usigned long to store overflow
			CLASS_DECLSPEC void AddMessageLength(unsigned long int);

			// Computes the chunk block of information  
			CLASS_DECLSPEC virtual void Compress(BaseCryptoRandomStream*, unsigned char*) {};

		public:

			// Constructor, default 
			CLASS_DECLSPEC BaseSha32();

			// Destructor
			CLASS_DECLSPEC ~BaseSha32();

			// Adds the BaseCryptoRandomStream to the hash
			CLASS_DECLSPEC void Add(BaseCryptoRandomStream*);

			// Finalize the hash
			CLASS_DECLSPEC void Finalize(void);
	};
  }
}

#endif

