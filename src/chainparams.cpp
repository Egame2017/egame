// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        pchMessageStart[0] = 0x2a;
        pchMessageStart[1] = 0x81;
        pchMessageStart[2] = 0x5b;
        pchMessageStart[3] = 0xc7;
        vAlertPubKey = ParseHex("0466d7648d499ebf0e485638df9754ad250a2392140a940700478cbf4aad746046b8c058822fa8b57ba5ad5b4ed7c1f73eb8916fafa0f96efd0d7b933701b38faf");
        vchSyncCheckpointPubKey = ParseHex("04194c5c2ccfe7c7629ef3361953168d153084958761449653b0118c6222fc88a0051ea8327077196fc8fba736b9b8b689ad96b2376e6b2f2a05be649164e6dcdd");
        nDefaultPort = 19178;
        nRPCPort = 19180;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        bnProofOfStakeLimit= CBigNum(~uint256(0) >> 20);

        const char* pszTimestamp = "Game on";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1496840400, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1496840400;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 7860;

        hashGenesisBlock = genesis.GetHash();
        
        assert(hashGenesisBlock == uint256("0x0000b6b57c90456ee758fac7f08bde6101ec4f109788beb92bc7ee713bffc2b8"));
        assert(genesis.hashMerkleRoot == uint256("0x23a7f95df7cc5f4180b686bed34b40000ef618432779226a9b3171df1518426b"));
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 33);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 92);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 161);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x58;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x79;
        pchMessageStart[3] = 0x17;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("04c4de2de66598742420cef692aff12686030977bd39a3bc037226eb7545a8a40cf9594d8818dc7b77d962e5360bcaf82c86d337cead66723187f9d67926a4fcd8");
        nDefaultPort = 17899;
        nRPCPort = 17891;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 443325;

        hashGenesisBlock = genesis.GetHash(); 
        
        assert(hashGenesisBlock == uint256("0x000069922a824ca85bd0baf30f62ccdb5c15c0a0adc9f4cf4547eb1a26771562"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 135);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 208);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 249);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1470000000;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 22212;
        strDataDir = "regtest";
		
		// If genesis block hash does not match, then generate new genesis hash.
        if (false) {
            LogPrintf("Searching for genesis block...\n");
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
            uint256 hashTarget = (~uint256(0) >> 2);
            while(true) {
                uint256 thash = genesis.GetHash();
                if (thash <= hashTarget)
                break;
                if ((genesis.nNonce & 0xFFF) == 0) {
                    LogPrintf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0) {
                    LogPrintf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            LogPrintf("TESTgenesis.nTime = %u \n", genesis.nTime);
            LogPrintf("genesis.nNonce = %u \n", genesis.nNonce);
            LogPrintf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
            LogPrintf("genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
		}

        assert(hashGenesisBlock == uint256("0x2a86229b7eede86874a2105777977102faa43478bddf7ef82b1631422a44d792"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
