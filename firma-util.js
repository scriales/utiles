var fs = require('fs');
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;
var dom = require('xmldom').DOMParser;
var select = require('xml-crypto').xpath;
var pemstrip = require('pemstrip');

var numeroArchivo = 1;

if (process.argv[2] !== undefined && process.argv[2] !== null) {
  numeroArchivo = process.argv[2];
}

fs.readFile(`./mensajes/rnf${numeroArchivo}.xml`, 'utf-8', function(err, xml) {
  if (err) {
    console.log('Error en la lectura del archivo: rnf' + numeroArchivo);
    console.log(err);
    return;
  }
  
  console.log('XML original');
  console.log(xml);
  var xmlPlano = xml.replace(/\n|\r| {2,}/g, '');
  console.log('XML plano');
  console.log(xmlPlano);

  var sig = new SignedXml();
  sig.addReference("//*[local-name(.)='Object']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], 'http://www.w3.org/2000/09/xmldsig#sha1');
  sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  sig.signatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  sig.signingKey = fs.readFileSync('./seguridad/privada.pem');
  sig.keyInfoProvider = new MyKeyInfo();
  sig.computeSignature(xmlPlano, {
    location: { reference: "//*[local-name(.)='Object']", action: "before" }
    //location: { reference: "/*[name()='Signature']", action: "before" }
  });

  console.log('XML Firmado');
  var xmlFirmado = sig.getSignedXml();
  var xmlDom = new dom().parseFromString(xmlFirmado);
  var signature = select(xmlDom, "/*[name()='Signature']")[0];
  var object = select(xmlDom, "/*[name()='Object']")[0];
  var signatureDom = new dom().parseFromString(signature.toString());
  var signatureElement = signatureDom.getElementsByTagName('Signature')[0];
  signatureElement.appendChild(object); 
  var xmlFirmadoEnveloping = signatureDom.toString();
  xmlFirmadoEnveloping = '<?xml version="1.0" encoding="UTF-8"?>' + xmlFirmadoEnveloping;
  console.log(xmlFirmadoEnveloping);

  fs.writeFileSync(`./mensajes/rnf${numeroArchivo}-firmado.xml`, xmlFirmadoEnveloping)
});

function MyKeyInfo() {
  this.getKeyInfo = function(key, prefix) {
    prefix = prefix || ''
    prefix = prefix ? prefix + ':' : prefix
    var publica = fs.readFileSync('./seguridad/publica.pem');
    var stripped = pemstrip.strip(publica);
    return "<" + prefix + "X509Data><X509Certificate>" + stripped.base64 + "</X509Certificate></" + prefix + "X509Data><KeyName>Ag3t1k</KeyName>"
  }
  this.getKey = function(keyInfo) {
    //you can use the keyInfo parameter to extract the key in any way you want 
    return fs.readFileSync("publica.pem")
  }
}
