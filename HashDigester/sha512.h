//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.4.0.0.1
//
// Copyright © 2009-2010 DiceLock Security, LLC. All rigths reserved.
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
// 
// DICELOCK IS A REGISTERED TRADEMARK OR TRADEMARK OF THE OWNERS.
// 

#ifndef SHA512_HPP

#define SHA512_HPP

#ifdef DICELOCKCIPHER_EXPORTS
   #define CLASS_DECLSPEC    __declspec(dllexport)
#else
   #define CLASS_DECLSPEC    __declspec(dllimport)
#endif

#include "baseHash.h"


#define SHA512_DIGESTBITS    512  // 512 hash bits
#define SHA512_DIGESTUCHARS  64   // 64  hash unsigned chars
#define SHA512_DIGESTUSHORTS 32   // 32  hash unsigned short ints
#define SHA512_DIGESTULONGS  16   // 16  hash unsigned long ints
#define SHA512_DIGESTULG64S  8    // 8   hash unsigned 64 bits

#define SHA512_DATABITS    1024    // 1024 block bits
#define SHA512_DATAUCHARS  128     // 128  block unsigned chars
#define SHA512_DATAUSHORTS 64      // 64   block unsigned longs ints
#define SHA512_DATAULONGS  32      // 32   block unsigned longs ints
#define SHA512_DATAULG64S  16      // 16   block unsigned 64 bits

#define SHA512_EQUATIONMODULO  896

#define SHA512_COMPUTECONSTANTS 80

#define SHA512_MESSAGESCHEDULE 80

#define SHA512_OPERATIONS 80

#define SHA512_ShiftRight(x, n) ((x)>>(n))

#define SHA512_SUM_0(x) (_rotr64(x, 28) ^ _rotr64(x, 34) ^ _rotr64(x, 39))
#define SHA512_SUM_1(x) (_rotr64(x, 14) ^ _rotr64(x, 18) ^ _rotr64(x, 41))
#define SHA512_SIG_0(x) (_rotr64(x, 1) ^ _rotr64(x, 8) ^ SHA512_ShiftRight(x, 7))
#define SHA512_SIG_1(x) (_rotr64(x, 19) ^ _rotr64(x, 61) ^ SHA512_ShiftRight(x, 6))

namespace DiceLockSecurity {

  namespace Hash {

	class Sha512 : public BaseHash {

		private:

			// Hash Algorithms Class enumerator name
			static const Hashes	hashName;

			// Number of hash bits
			static const unsigned short int hashBits;
			// Number of hash unsigned chars
			static const unsigned short int hashUCs;
			// Number of hash unsigned short ints
			static const unsigned short int hashUSs;
			// Number of hash unsigned long ints
			static const unsigned short int hashULs;
			// Number of hash unsigned 64 bits
			static const unsigned short int hash64s;

			// Number of schedule words
			static const unsigned short int scheduleNumber;

			// Initial hash values of SHA512 
			static const unsigned __int64 initials[SHA512_DIGESTULONGS];

			// Computational constant values of SHA512 
			static const unsigned __int64 constants[SHA512_COMPUTECONSTANTS];

			// Message schedule words for SHA512 
			unsigned __int64 messageSchedule[SHA512_MESSAGESCHEDULE];

		protected:

			// Number of data bits to compute hash
			static const unsigned short int dataHashBits;
			// Number of data unsigned chars to compute hash
			static const unsigned short int dataHashUCs;
			// Number of data unsigned long integers to compute hash
			static const unsigned short int dataHashULs;
			// Number of data unsigned 64 bit to compute hash
			static const unsigned short int dataHash64s;

			// Equation modulo constant value
			static const unsigned short int equationModulo;

			// Array to store remaining bytes of intermediate hash operation
			unsigned char remainingBytes[SHA512_DATAUCHARS];
			unsigned long int remainingBytesLength;

			// Total processed message length in bytes
			unsigned __int64 messageBitLengthHigh;
			unsigned __int64 messageBitLengthLow;

			// Adds messaage length processed, if it is greater than unsigned long makes use
			// of another unsigned long to store overflow
			CLASS_DECLSPEC void AddMessageLength(unsigned long int);

			// Gets the number of unsigned chars in the hash block to be hashed
			CLASS_DECLSPEC unsigned short int GetDataHashUCs(void);

			// Computes the chunk block of information  
			CLASS_DECLSPEC void Compress(BaseCryptoRandomStream*, unsigned char*);

		public:

			// Constructor, default 
			CLASS_DECLSPEC Sha512();

			// Destructor
			CLASS_DECLSPEC ~Sha512();

			// Initializes common states of Sha1 algorithm
			CLASS_DECLSPEC void Initialize(void);

			// Adds the BaseCryptoRandomStream to the hash
			CLASS_DECLSPEC void Add(BaseCryptoRandomStream*);

			// Finalize the hash
			CLASS_DECLSPEC void Finalize(void);

			// Gets hash length in bits
			CLASS_DECLSPEC unsigned short int GetBitHashLength(void);

			// Gets hash length in unsigned chars
			CLASS_DECLSPEC unsigned short int GetUCHashLength(void);

			// Gets hash length in unsigned short ints
			CLASS_DECLSPEC unsigned short int GetUSHashLength(void);

			// Gets hash length in unsigned long ints
			CLASS_DECLSPEC unsigned short int GetULHashLength(void);

			// Gets hash length in unsigned 64 bits
			CLASS_DECLSPEC unsigned short int Get64HashLength(void);

			// Gets the type of the object
			CLASS_DECLSPEC Hashes GetType(void);
	};
  }
}

#endif
