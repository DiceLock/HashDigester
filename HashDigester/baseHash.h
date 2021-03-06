//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.6.0.0.1
//
// Copyright � 2009-2012 DiceLock Security, LLC. All rights reserved.
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

#ifndef BASEHASH_HPP

#define BASEHASH_HPP

#ifdef DICELOCKCIPHER_EXPORTS
   #define CLASS_DECLSPEC    __declspec(dllexport)
#else
   #define CLASS_DECLSPEC    __declspec(dllimport)
#endif

#include "baseCryptoRandomStream.h"

using namespace DiceLockSecurity;
using namespace DiceLockSecurity::CryptoRandomStream;


namespace DiceLockSecurity {

  namespace Hash {

	enum Hashes {
		SHA_1,
		SHA_224,
		SHA_256,
		SHA_384,
		SHA_512,
		RIPEMD_128,
		RIPEMD_160,
		RIPEMD_256,
		RIPEMD_320,
		NumberOfHashes,		// Indication of the number of hash alforithms, any added hash algorithm must be inserted before
		NotDefined,
	};

	class BaseHash abstract {

		protected:

			/// Pointer to BaseCryptoRandomStream digest
			BaseCryptoRandomStream* messageDigest; 

		public:

			/// Constructor, default 
			CLASS_DECLSPEC BaseHash();

			/// Constructor assigning diggest BaseCryptoRandomStream 
			CLASS_DECLSPEC BaseHash(BaseCryptoRandomStream*);

			/// Destructor
			CLASS_DECLSPEC virtual ~BaseHash();

			/// Set the Message Digest BaseCryptoRandomStream
			CLASS_DECLSPEC void SetMessageDigest(BaseCryptoRandomStream*);

			/// Initialize BaseHash
			CLASS_DECLSPEC virtual void Initialize() {};

			/// Adds the BaseCryptoRandomStream 
			CLASS_DECLSPEC virtual void Add(BaseCryptoRandomStream*) {};

			/// Finalize the hash
			CLASS_DECLSPEC virtual void Finalize(void) {};

			/// Gets the hash 
			CLASS_DECLSPEC BaseCryptoRandomStream* GetMessageDigest(void);

			/// Gets hash length in bits
			CLASS_DECLSPEC virtual unsigned short int GetBitHashLength(void) {return 0;};

			/// Gets hash length in unsigned chars
			CLASS_DECLSPEC virtual unsigned short int GetUCHashLength(void) {return 0;};

			/// Gets hash length in unsigned short ints
			CLASS_DECLSPEC virtual unsigned short int GetUSHashLength(void) {return 0;};

			/// Gets hash length in unsigned long ints
			CLASS_DECLSPEC virtual unsigned short int GetULHashLength(void) {return 0;};

			/// Gets the number of bits in the hash block to be hashed
			CLASS_DECLSPEC virtual unsigned short int GetBitHashBlockLength(void) {return 0;};

			/// Gets the number of unsigned chars in the hash block to be hashed
			CLASS_DECLSPEC virtual unsigned short int GetUCHashBlockLength(void) {return 0;};

			/// Gets the number of unsigned short ints in the hash block to be hashed
			CLASS_DECLSPEC virtual unsigned short int GetUSHashBlockLength(void) {return 0;};

			/// Gets the number of unsigned long ints in the hash block to be hashed
			CLASS_DECLSPEC virtual unsigned short int GetULHashBlockLength(void) {return 0;};

			/// Gets the type of the object
			CLASS_DECLSPEC virtual Hashes GetType(void) {return NotDefined;};
	};
  }
}

#endif
