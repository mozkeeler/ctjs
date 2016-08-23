"use strict";

class Root {
  constructor(organization, organizationalUnit, commonName) {
    this.organization = organization;
    this.organizationalUnit = organizationalUnit;
    this.commonName = commonName;
  }

  get id() {
    let o = this.organization;
    let ou = this.organizationalUnit;
    let cn = this.commonName;
    return `${o.length}${o}${ou.length}${ou}${cn.length}${cn}`;
  }
}

var mozillaRoots = {};

function addRoot(organization, organizationalUnit, commonName) {
  let root = new Root(organization, organizationalUnit, commonName);
  mozillaRoots[root.id] = root;
}

// ca must have the properties 'organization', 'organizationalUnit', and
// 'commonName'. They may be empty strings.
exports.isMozillaRoot = function isMozillaRoot(ca) {
  let root = new Root(ca.organization, ca.organizationalUnit, ca.commonName);
  return root.id in mozillaRoots;
}

addRoot("Actalis S.p.A./03358520967", "", "Actalis Authentication Root CA");
addRoot("Starfield Technologies, Inc.", "", "Starfield Services Root Certificate Authority - G2");
addRoot("AS Sertifitseerimiskeskus", "", "EE Certification Centre Root CA");
addRoot("AS Sertifitseerimiskeskus", "", "Juur-SK");
addRoot("Unizeto Sp. z o.o.", "", "Certum CA");
addRoot("Unizeto Technologies S.A.", "Certum Certification Authority", "Certum Trusted Network CA");
addRoot("Unizeto Technologies S.A.", "Certum Certification Authority", "Certum Trusted Network CA 2");
addRoot("Atos", "", "Atos TrustedRoot 2011");
addRoot("Autoridad de Certificacion Firmaprofesional", "", "Autoridad de Certificacion Firmaprofesional CIF A62634068");
addRoot("Buypass AS-983163327", "", "Buypass Class 2 CA 1");
addRoot("Buypass AS-983163327", "", "Buypass Class 2 Root CA");
addRoot("Buypass AS-983163327", "", "Buypass Class 3 Root CA");
addRoot("Disig a.s.", "", "CA Disig Root R1");
addRoot("Disig a.s.", "", "CA Disig Root R2");
addRoot("AC Camerfirma SA CIF A82743287", "http://www.chambersign.org", "Chambers of Commerce Root");
addRoot("AC Camerfirma S.A.", "", "Chambers of Commerce Root - 2008");
addRoot("AC Camerfirma SA CIF A82743287", "http://www.chambersign.org", "Global Chambersign Root");
addRoot("AC Camerfirma S.A.", "", "Global Chambersign Root - 2008");
addRoot("Certinomis", "0002 433998903", "Certinomis - Autorité Racine");
addRoot("Certinomis", "0002 433998903", "Certinomis - Root CA");
addRoot("certSIGN", "certSIGN ROOT CA", "certSIGN ROOT CA");
addRoot("China Financial Certification Authority", "", "CFCA EV ROOT");
addRoot("China Internet Network Information Center", "", "China Internet Network Information Center EV Certificates Root");
addRoot("CNNIC", "", "CNNIC ROOT");
addRoot("Chunghwa Telecom Co., Ltd.", "ePKI Root Certification Authority", "ePKI Root Certification Authority");
addRoot("Comodo CA Limited", "", "AAA Certificate Services");
addRoot("AddTrust AB", "AddTrust TTP Network", "AddTrust Class 1 CA Root");
addRoot("AddTrust AB", "AddTrust External TTP Network", "AddTrust External CA Root");
addRoot("AddTrust AB", "AddTrust TTP Network", "AddTrust Public CA Root");
addRoot("AddTrust AB", "AddTrust TTP Network", "AddTrust Qualified CA Root");
addRoot("COMODO CA Limited", "", "COMODO Certification Authority");
addRoot("COMODO CA Limited", "", "COMODO ECC Certification Authority");
addRoot("COMODO CA Limited", "", "COMODO RSA Certification Authority");
addRoot("Comodo CA Limited", "", "Secure Certificate Services");
addRoot("Comodo CA Limited", "", "Trusted Certificate Services");
addRoot("The USERTRUST Network", "", "USERTrust ECC Certification Authority");
addRoot("The USERTRUST Network", "", "USERTrust RSA Certification Authority");
addRoot("The USERTRUST Network", "http://www.usertrust.com", "UTN-USERFirst-Hardware");
addRoot("Agencia Catalana de Certificacio (NIF Q-0801176-I)", "Jerarquia Entitats de Certificacio Catalanes", "EC-ACC");
addRoot("Japan Certification Services, Inc.", "", "SecureSign RootCA11");
addRoot("D-Trust GmbH", "", "D-TRUST Root Class 3 CA 2 2009");
addRoot("D-Trust GmbH", "", "D-TRUST Root Class 3 CA 2 EV 2009");
addRoot("Dhimyotis", "", "Certigna");
addRoot("Baltimore", "CyberTrust", "Baltimore CyberTrust Root");
addRoot("Cybertrust, Inc", "", "Cybertrust Global Root");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Assured ID Root CA");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Assured ID Root G2");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Assured ID Root G3");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Global Root CA");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Global Root G2");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Global Root G3");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert High Assurance EV Root CA");
addRoot("DigiCert Inc", "www.digicert.com", "DigiCert Trusted Root G4");
addRoot("Certplus", "", "Certplus Root CA G1");
addRoot("Certplus", "", "Certplus Root CA G2");
addRoot("Certplus", "", "Class 2 Primary CA");
addRoot("OpenTrust", "", "OpenTrust Root CA G1");
addRoot("OpenTrust", "", "OpenTrust Root CA G2");
addRoot("OpenTrust", "", "OpenTrust Root CA G3");
addRoot("E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş.", "E-Tugra Sertifikasyon Merkezi", "E-Tugra Certification Authority");
addRoot("EBG Bilişim Teknolojileri ve Hizmetleri A.Ş.", "", "EBG Elektronik Sertifika Hizmet Sağlayıcısı");
addRoot("EDICOM", "PKI", "ACEDICOM Root");
addRoot("AffirmTrust", "", "AffirmTrust Commercial");
addRoot("AffirmTrust", "", "AffirmTrust Networking");
addRoot("AffirmTrust", "", "AffirmTrust Premium");
addRoot("AffirmTrust", "", "AffirmTrust Premium ECC");
addRoot("Entrust, Inc.", "(c) 2006 Entrust, Inc.", "Entrust Root Certification Authority");
addRoot("Entrust, Inc.", "(c) 2012 Entrust, Inc. - for authorized use only", "Entrust Root Certification Authority - EC1");
addRoot("Entrust, Inc.", "(c) 2009 Entrust, Inc.-for authorized use only", "Entrust Root Certification Authority - G2");
// This one actually has two OUs, so this gets turned into two entries? Maybe
// that will work?
addRoot("Entrust.net", "(c) 1999 Entrust.net Limited", "Entrust.net Certification Authority (2048)");
addRoot("Entrust.net", "www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)", "Entrust.net Certification Authority (2048)");
//
addRoot("GlobalSign", "GlobalSign ECC Root CA - R4", "GlobalSign ECC Root CA - R4");
addRoot("GlobalSign", "GlobalSign ECC Root CA - R5", "GlobalSign ECC Root CA - R5");
addRoot("GlobalSign nv-sa", "Root CA", "GlobalSign Root CA");
addRoot("GlobalSign", "GlobalSign Root CA - R2", "GlobalSign Root CA - R2");
addRoot("GlobalSign", "GlobalSign Root CA - R3", "GlobalSign Root CA - R3");
addRoot("The Go Daddy Group, Inc.", "Go Daddy Class 2 Certification Authority", "Go Daddy Class 2 CA");
addRoot("GoDaddy.com, Inc.", "", "Go Daddy Root Certificate Authority - G2");
addRoot("Starfield Technologies, Inc.", "Starfield Class 2 Certification Authority", "Starfield Class 2 CA");
addRoot("Starfield Technologies, Inc.", "", "Starfield Root Certificate Authority - G2");
addRoot("PM/SGDN", "DCSSI (new name is ANSSI)", "IGC/A");
addRoot("Hongkong Post", "", "Hongkong Post Root CA 1");
addRoot("Japanese Government", "ApplicationCA", "Japanese Government ApplicationCA");
addRoot("ACCV", "PKIACCV", "ACCVRAIZ1");
addRoot("Generalitat Valenciana", "PKIGVA", "Root CA Generalitat Valenciana");
addRoot("Government Root Certification Authority", "", "Taiwan Government Root Certification Authority");
addRoot("Staat der Nederlanden", "", "Staat der Nederlanden EV Root CA");
addRoot("Staat der Nederlanden", "", "Staat der Nederlanden Root CA - G2");
addRoot("Staat der Nederlanden", "", "Staat der Nederlanden Root CA - G3");
addRoot("Türkiye Bilimsel ve Teknolojik Araştırma Kurumu - TÜBİTAK", "Kamu Sertifikasyon Merkezi", "TÜBİTAK UEKAE Kök Sertifika Hizmet Sağlayıcısı - Sürüm 3");
addRoot("Hellenic Academic and Research Institutions Cert. Authority", "", "Hellenic Academic and Research Institutions ECC RootCA 2015");
addRoot("Hellenic Academic and Research Institutions Cert. Authority", "", "Hellenic Academic and Research Institutions RootCA 2011");
addRoot("Hellenic Academic and Research Institutions Cert. Authority", "", "Hellenic Academic and Research Institutions RootCA 2015");
addRoot("Digital Signature Trust", "DST ACES", "DST ACES CA X6");
addRoot("Digital Signature Trust Co.", "", "DST Root CA X3");
addRoot("IdenTrust", "", "IdenTrust Commercial Root CA 1");
addRoot("IdenTrust", "", "IdenTrust Public Sector Root CA 1");
addRoot("IZENPE S.A.", "", "Izenpe.com");
addRoot("Krajowa Izba Rozliczeniowa S.A.", "", "SZAFIR ROOT CA2");
addRoot("Microsec Ltd.", "e-Szigno CA", "Microsec e-Szigno Root CA");
addRoot("Microsec Ltd.", "", "Microsec e-Szigno Root CA 2009");
addRoot("NetLock Kft.", "Tanúsítványkiadók (Certification Services)", "NetLock Arany (Class Gold) Főtanúsítvány");
addRoot("Sistema Nacional de Certificacion Electronica", "Superintendencia de Servicios de Certificacion Electronica", "PSCProcert");
addRoot("QuoVadis Limited", "", "QuoVadis Root CA 1 G3");
addRoot("QuoVadis Limited", "", "QuoVadis Root CA 2");
addRoot("QuoVadis Limited", "", "QuoVadis Root CA 2 G3");
addRoot("QuoVadis Limited", "", "QuoVadis Root CA 3");
addRoot("QuoVadis Limited", "", "QuoVadis Root CA 3 G3");
addRoot("QuoVadis Limited", "Root Certification Authority", "QuoVadis Root Certification Authority");
addRoot("RSA Security Inc", "RSA Security 2048 V3", "RSA Security 2048 v3");
addRoot("SECOM Trust Systems CO.,LTD.", "Security Communication EV RootCA1", "Security Communication EV RootCA1");
addRoot("SECOM Trust.net", "Security Communication RootCA1", "Security Communication RootCA1");
addRoot("SECOM Trust Systems CO.,LTD.", "Security Communication RootCA2", "Security Communication RootCA2");
addRoot("StartCom Ltd.", "Secure Digital Certificate Signing", "StartCom Certification Authority");
addRoot("StartCom Ltd.", "Secure Digital Certificate Signing", "StartCom Certification Authority");
addRoot("StartCom Ltd.", "", "StartCom Certification Authority G2");
addRoot("Swisscom", "Digital Certificate Services", "Swisscom Root CA 1");
addRoot("Swisscom", "Digital Certificate Services", "Swisscom Root CA 2");
addRoot("Swisscom", "Digital Certificate Services", "Swisscom Root EV CA 2");
addRoot("SwissSign AG", "", "SwissSign Gold CA - G2");
addRoot("SwissSign AG", "", "SwissSign Silver CA - G2");
addRoot("GeoTrust Inc.", "", "GeoTrust Global CA");
addRoot("GeoTrust Inc.", "", "GeoTrust Global CA 2");
addRoot("GeoTrust Inc.", "", "GeoTrust Primary Certification Authority");
addRoot("GeoTrust Inc.", "(c) 2007 GeoTrust Inc. - For authorized use only", "GeoTrust Primary Certification Authority - G2");
addRoot("GeoTrust Inc.", "(c) 2008 GeoTrust Inc. - For authorized use only", "GeoTrust Primary Certification Authority - G3");
addRoot("GeoTrust Inc.", "", "GeoTrust Universal CA");
addRoot("GeoTrust Inc.", "", "GeoTrust Universal CA 2");
addRoot("thawte, Inc.", "(c) 2006 thawte, Inc. - For authorized use only", "thawte Primary Root CA");
addRoot("thawte, Inc.", "(c) 2007 thawte, Inc. - For authorized use only", "thawte Primary Root CA - G2");
addRoot("thawte, Inc.", "(c) 2008 thawte, Inc. - For authorized use only", "thawte Primary Root CA - G3");
addRoot("VeriSign, Inc.", "(c) 1999 VeriSign, Inc. - For authorized use only", "VeriSign Class 3 Public Primary Certification Authority - G3");
addRoot("VeriSign, Inc.", "(c) 2007 VeriSign, Inc. - For authorized use only", "VeriSign Class 3 Public Primary Certification Authority - G4");
addRoot("VeriSign, Inc.", "(c) 2006 VeriSign, Inc. - For authorized use only", "VeriSign Class 3 Public Primary Certification Authority - G5");
addRoot("VeriSign, Inc.", "(c) 2008 VeriSign, Inc. - For authorized use only", "VeriSign Universal Root Certification Authority");
addRoot("Deutsche Telekom AG", "T-TeleSec Trust Center", "Deutsche Telekom Root CA 2");
addRoot("T-Systems Enterprise Services GmbH", "T-Systems Trust Center", "T-TeleSec GlobalRoot Class 2");
addRoot("T-Systems Enterprise Services GmbH", "T-Systems Trust Center", "T-TeleSec GlobalRoot Class 3");
addRoot("TAIWAN-CA", "Root CA", "TWCA Global Root CA");
addRoot("TAIWAN-CA", "Root CA", "TWCA Root Certification Authority");
addRoot("Sonera", "", "Sonera Class2 CA");
addRoot("TeliaSonera", "", "TeliaSonera Root CA v1");
addRoot("Trustis Limited", "Trustis FPS Root CA", "Trustis FPS Root CA");
addRoot("SecureTrust Corporation", "", "Secure Global CA");
addRoot("SecureTrust Corporation", "", "SecureTrust CA");
addRoot("XRamp Security Services Inc", "www.xrampsecurity.com", "XRamp Global Certification Authority");
addRoot("TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A.Ş. (c) Aralık 2007", "", "TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı 2");
addRoot("TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A.Ş.", "", "TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı H5");
addRoot("TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A.Ş.", "", "TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı H6");
addRoot("VISA", "Visa International Service Association", "Visa eCommerce Root");
addRoot("Network Solutions L.L.C.", "", "Network Solutions Certificate Authority");
addRoot("Wells Fargo WellsSecure", "Wells Fargo Bank NA", "WellsSecure Public Root Certificate Authority");
addRoot("WISeKey", "OISTE Foundation Endorsed", "OISTE WISeKey Global Root GA CA");
addRoot("WISeKey", "OISTE Foundation Endorsed", "OISTE WISeKey Global Root GB CA");
addRoot("WoSign CA Limited", "", "CA WoSign ECC Root");
addRoot("WoSign CA Limited", "", "CA 沃通根证书");
addRoot("WoSign CA Limited", "", "Certification Authority of WoSign");
addRoot("WoSign CA Limited", "", "Certification Authority of WoSign G2");
