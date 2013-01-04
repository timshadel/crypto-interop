/*
 * Public: Utility to sign data with a private key or verify data with a
 * public key.
 *
 * Examples
 *
 *   node signature.js sign   ~/data ~/my_key.pem ~/data.sig
 *   node signature.js verify ~/data ~/data.sig ~/my_key.crt
 */

var crypto = require('crypto');
var fs     = require('fs');

/* Public: The single, agreed signature algorithm among participants. */
var SIGNATURE_ALGORITHM = 'RSA-SHA256';

/*
 * Private: Prints expected command line invocation and exits.
 *
 * Returns nothing.
 * Exits the program with non-zero status.
 */
var usage = function () {
  console.log("Usage:");
  console.log("  node signature.js sign   [data file] [private key file] [signature output file]");
  console.log("  node signature.js verify [data file] [signature file] [public key file]");
  process.exit(-1);
};

/*
 * Private: Handle an error condition by printing it and exiting with a
 * non-zero status.
 *
 * err - any expression which, if truthy, indicates an error
 *
 * Examples
 *
 *   someFunctionWithCallback(function(err) {
 *     handleErr(err);
 *     ...
 *   });
 *
 * Returns nothing.
 * Exits the program if err is truthy.
 */
var handleError = function(err) {
  if (err) {
    console.log("Error", err);
    process.exit(-1);
  }
};

/*
 * Public: Use the private key to sign the given data. Save the
 * signature in a file.
 *
 * dataPath       - filesystem path to the data
 * privateKeyPath - filesystem path to the private key in PEM format
 * signaturePath  - filesystem path to which the signature should be written
 *
 * Examples
 *
 *   sign('~/data', '~/my_key.pem', '~/data.sig');
 *
 * Returns nothing.
 */
var sign = function (dataPath, privateKeyPath, signaturePath) {

  console.log("Loading data from '" + dataPath + "'");
  fs.readFile(dataPath, function(err, data) {
    handleError(err);

    console.log("Loading data from '" + privateKeyPath + "'");
    fs.readFile(privateKeyPath, function(err, privateKey) {
      handleError(err);

      console.log("Signing data");
      console.log(data.toString('hex'), '\n');
      console.log("Using private key");
      console.log(privateKey.toString('hex'), '\n');

      var signer = crypto.createSign(SIGNATURE_ALGORITHM);
      signer.update(data);
      var signature = new Buffer(signer.sign(privateKey), 'binary');

      console.log("Signature Bytes");
      console.log(signature.toString('hex'), '\n');

      console.log("Signature Encoded as Base64");
      var signature_b64 = signature.toString('base64');
      console.log(signature_b64, '\n');

      fs.writeFile(signaturePath, signature_b64, function(err) {
        console.log("Base64 Signature saved to '" + signaturePath + "'");
      });
    });

  });

};

/*
 * Public: Use the public key to check the signature of the given data.
 *
 * dataPath      - filesystem path to the data
 * signaturePath - filesystem path to the signature to check
 * publicKeyPath - filesystem path to the public key or certificate in PEM format
 *
 * Examples
 *
 *   verify('~/data', '~/data.sig', '~/my_key.pem');
 *
 * Returns `true` if the signature is valid, `false` otherwise.
 */
var verify = function (dataPath, signaturePath, publicKeyPath) {
  console.log("Loading data from '" + dataPath + "'");
  fs.readFile(dataPath, function(err, data) {
    handleError(err);

    console.log("Loading signature from '" + signaturePath + "'");
    fs.readFile(signaturePath, 'utf8', function(err, signature) {
      handleError(err);

      console.log("Loading public key from '" + publicKeyPath + "'");
      fs.readFile(publicKeyPath, function(err, publicKey) {
        handleError(err);

        console.log("Verifying signature");
        console.log(signature, '\n');
        console.log("Over data");
        console.log(data.toString('hex'), '\n');
        console.log("Using public key");
        console.log(publicKey.toString('hex'), '\n');

        var verifier = crypto.createVerify(SIGNATURE_ALGORITHM);
        verifier.update(data);
        var valid = verifier.verify(publicKey, signature, 'base64');

        console.log("Signature valid?", valid);
        process.exit(valid ? 0 : -1);
      });

    });

  });

};

/*
 * Private: Handle the program's command line arguments to call
 * the appropriate functions.
 *
 * Returns nothing.
 */
var processArgs = function () {
  if (process.argv.length === 6 && process.argv[2] === 'sign') {
    sign(process.argv[3], process.argv[4], process.argv[5]);
  } else if (process.argv.length === 6 && process.argv[2] === 'verify') {
    verify(process.argv[3], process.argv[4], process.argv[5]);
  } else {
    usage();
  }
};

processArgs();
