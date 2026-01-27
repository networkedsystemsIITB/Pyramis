#include <iostream>
#include <iterator>
#include <map>

using namespace std;

map<int, int> keyToFdMap;
map<int, pair<struct sockaddr_in *, int>> keyToIpFdMap;

typedef struct UeContextMapTempstructure {
	_5gRegistrationType_t _5gregType;
	NaskeysetId_t ngKsi;
	nssai_t requestedNssai;
	string suci;
	}UeContextMapTempstructure_t;

map<RAN_UE_NGAP_ID_t, UeContextMapTempstructure_t> UeContextMapTemp;

typedef struct UeContextMapstructure {
	RAN_UE_NGAP_ID_t ranUeNgapId;
	string suci;
	_5gRegistrationType_t _5gregType;
	NaskeysetId_t ngKsi;
	nssai_t requestedNssai;
	UeSecurityCapability_t ueSecurityCapability;
	string state;
	string RAND;
	string hxresStar;
	string kSeaf;
	string autn;
	string authCtxId;
	uint8_t* resStar;
	string supi;
	nssai_t allowedNssai;
	rejectedNssai_t rejectedNssai;
	bool isSuccess;
	}UeContextMapstructure_t;

map<AmfUeNgapId_t, UeContextMapstructure_t> UeContextMap;

typedef struct SuciAmfUeNgapIdMapstructure {
	AmfUeNgapId_t amfUeNgapId;
	}SuciAmfUeNgapIdMapstructure_t;

map<string, SuciAmfUeNgapIdMapstructure_t> SuciAmfUeNgapIdMap;

typedef struct globalContextMapstructure {
	string ausf_ip;
	string udm_ip;
	}globalContextMapstructure_t;

map<string, globalContextMapstructure_t> globalContextMap;

typedef struct SupiAmfUeNgapIdMapstructure {
	int amfUeNgapId;
	}SupiAmfUeNgapIdMapstructure_t;

map<string, SupiAmfUeNgapIdMapstructure_t> SupiAmfUeNgapIdMap;

