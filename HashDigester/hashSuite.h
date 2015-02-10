//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.6.0.0.1
//
// Copyright © 2009-2012 DiceLock Security, LLC. All rights reserved.
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

#ifndef HASHSUITE_HPP

#define HASHSUITE_HPP

#ifdef DICELOCKCIPHER_EXPORTS
   #define CLASS_DECLSPEC    __declspec(dllexport)
#else
   #define CLASS_DECLSPEC    __declspec(dllimport)
#endif

#include "hashDigester.h"


namespace DiceLockSecurity {

  namespace Hash {

	  class HashSuite {

		protected:

			/// Points the first hash algorithm in the suite
			static const	Hashes firstHash;

			BaseHash*			suite[NumberOfHashes];
			bool				selfCreatedHash[NumberOfHashes];
			unsigned short int	instantiatedHashes;

		public:

			/// Constructor, default, initializes suite 
			CLASS_DECLSPEC HashSuite();

			/// Destructor
			CLASS_DECLSPEC ~HashSuite();

			// ADDING HASHES
			
			/// Adds a hash to the suite
			CLASS_DECLSPEC void Add(BaseHash*);

			/// Creates and adds a hash to the suite based in the enumerated hash list
			CLASS_DECLSPEC void Add(Hashes);

			/// Creates and adds all hash algorithms to the suite
			CLASS_DECLSPEC void AddAll(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddSha1(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddSha224(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddSha256(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddSha384(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddSha512(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddRipemd128(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddRipemd160(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddRipemd256(void);

			/// Creates and adds the defined hash to the suite
			CLASS_DECLSPEC void AddRipemd320(void);

			// GETTING HASH OBJECT
			
			/// Gets a hash algorithm from the suite based in the enumerated hash
			CLASS_DECLSPEC BaseHash* GetMessageDigest(Hashes);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Sha1* GetSha1(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Sha224* GetSha224(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Sha256* GetSha256(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Sha384* GetSha384(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Sha512* GetSha512(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Ripemd128* GetRipemd128(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Ripemd160* GetRipemd160(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Ripemd256* GetRipemd256(void);

			/// Gets the defined hash from the suite
			CLASS_DECLSPEC Ripemd320* GetRipemd320(void);

			// REMOVING HASH ALGORITHMS

			/// Removes the pointed hash from the suite
			CLASS_DECLSPEC void Remove(BaseHash*);

			/// Removes a hash from the suite based in the enumerated hash algorithms
			CLASS_DECLSPEC void Remove(Hashes);

			/// Removes all hash algorithms from the suite
			CLASS_DECLSPEC void RemoveAll(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveSha1(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveSha224(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveSha256(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveSha384(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveSha512(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveRipemd128(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveRipemd160(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveRipemd256(void);

			/// Removes the defined hash from the suite
			CLASS_DECLSPEC void RemoveRipemd320(void);

			// PERFORMING HASH

			/// Performs the hash algorithms of BaseCryptoRandomStream with all instantiated hash 
			CLASS_DECLSPEC void Hash(BaseCryptoRandomStream*);

			// INITIALIZE SUITE
			
			/// Initializes all hash algorithms in the suite
			CLASS_DECLSPEC void Initialize(void);

			// ADDS STREAM TO THE SUITE
			
			/// Adds BaseCryptoRandomStream stream to hash algorithms in the suite
			CLASS_DECLSPEC void Add(BaseCryptoRandomStream*);

			// FINALIZE THE SUITE
			
			/// Finalize hash algorithms in the suite
			CLASS_DECLSPEC void Finalize(void);

			// GETTING SUITE INFORMATION

			/// Gets the number of hash algorithms that contains the suite
			CLASS_DECLSPEC unsigned long int GetInstantiatedHashes(void);

			/// Indicates if a hash algorithm exists in the suite
			CLASS_DECLSPEC bool Exist(Hashes);

			/// Gets the first hash algorithm in the HashSuite
			CLASS_DECLSPEC Hashes GetFirstHash(void);

			/// Gets the number of hash algorithms that can be used in the HahsSuite
			CLASS_DECLSPEC Hashes GetMaximumNumberOfHashes(void);
	};
  }
}

#endif
