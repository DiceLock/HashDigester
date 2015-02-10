//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.5.0.0.1
//
// Copyright © 2009-2011 DiceLock Security, LLC. All rights reserved.
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

#ifndef SHA384_HPP

#define SHA384_HPP

#ifdef DICELOCKCIPHER_EXPORTS
   #define CLASS_DECLSPEC    __declspec(dllexport)
#else
   #define CLASS_DECLSPEC    __declspec(dllimport)
#endif

#include "sha512.h"
#include "defaultCryptoRandomStream.h"


#define SHA384_DIGESTBITS    384  // 384 hash bits
#define SHA384_DIGESTUCHARS  48   // 48  hash unsigned chars
#define SHA384_DIGESTUSHORTS 24   // 24  hash unsigned short ints
#define SHA384_DIGESTULONGS  12   // 12  hash unsigned long ints
#define SHA384_DIGESTULG64S  6    // 6   hash unsigned 64 bits


namespace DiceLockSecurity {

  namespace Hash {

	class Sha384 : public Sha512 {

		private:

			/// Hash Algorithms Class enumerator name
			static const Hashes	hashName;

			/// Number of hash bits
			static const unsigned short int hashBits;
			/// Number of hash unsigned chars
			static const unsigned short int hashUCs;
			/// Number of hash unsigned short ints
			static const unsigned short int hashUSs;
			/// Number of hash unsigned long ints
			static const unsigned short int hashULs;
			/// Number of hash unsigned 64 bits
			static const unsigned short int hash64s;

			/// Initial hash values of SHA512 
			static const unsigned __int64 initials[SHA384_DIGESTULONGS];

			/// Pointer to BaseCryptoRandomStream digest for SHA 384 hash algorithm
			BaseCryptoRandomStream* workingDigest512; 
			
			/// Boolean pointing if meesaageDigest for SHA 512 has been created automatically
			bool autoWorkingDigest;
			
		public:

			/// Constructor, default 
			CLASS_DECLSPEC Sha384();

			/// Destructor
			CLASS_DECLSPEC ~Sha384();

			/// Set the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm
			CLASS_DECLSPEC void SetWorkingDigest(BaseCryptoRandomStream*);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in bits
			CLASS_DECLSPEC unsigned short int GetWorkingDigestBitLength(void);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in unsigned chars
			CLASS_DECLSPEC unsigned short int GetWorkingDigestUCLength(void);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in unsigned short ints
			CLASS_DECLSPEC unsigned short int GetWorkingDigestUSLength(void);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in unsigned long ints
			CLASS_DECLSPEC unsigned short int GetWorkingDigestULLength(void);

			/// Initializes common states of Sha1 algorithm
			CLASS_DECLSPEC void Initialize(void);

			/// Adds the BaseCryptoRandomStream to the hash
			CLASS_DECLSPEC void Add(BaseCryptoRandomStream*);

			/// Finalize the hash
			CLASS_DECLSPEC void Finalize(void);

			/// Gets hash length in bits
			CLASS_DECLSPEC unsigned short int GetBitHashLength(void);

			/// Gets hash length in unsigned chars
			CLASS_DECLSPEC unsigned short int GetUCHashLength(void);

			/// Gets hash length in unsigned short ints
			CLASS_DECLSPEC unsigned short int GetUSHashLength(void);

			/// Gets hash length in unsigned long ints
			CLASS_DECLSPEC unsigned short int GetULHashLength(void);

			/// Gets hash length in unsigned 64 bits
			CLASS_DECLSPEC unsigned short int Get64HashLength(void);

			/// Gets the type of the object
			CLASS_DECLSPEC Hashes GetType(void);
	};
  }
}

#endif
