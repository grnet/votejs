/*
Automatically download and extract verificatum library as a commonjs module
in `vendor/verificatum` lib. Each verificatum namespace is destructed as a
nested module in order to be able to import things in modern js way such as::

``` import { LargeInteger } from "verificatum/arithm"; ```

Script also handles generation of empty `*.d.ts` definition files in
`vendor/@types/verificatum/*`
*/

const path = require("path");
const fs = require("fs");
const nodeCrypto= require("crypto");
const http = require("request-promise-native");
const mkdirp = require("mkdirp");

const VERIFICATUM_URL = "https://www.verificatum.com/files/vjsc-1.1.1.js";
const VERIFICATUM_MD5 = "3ef89c791e928904f681864d14ac7c90";
const VERIFICATUM_FILE = 'lib.js';
const VERIFICATUM_DIR = "vendor/verificatum";
const CHECKSUM_FILE = path.join(VERIFICATUM_DIR, VERIFICATUM_FILE + '.orig');
const STRICT_SSL = false;
const VERIFICATUM = path.join(VERIFICATUM_DIR, VERIFICATUM_FILE)

function ensureDir() {
  if (!fs.existsSync(VERIFICATUM_DIR)) {
    mkdirp.sync(VERIFICATUM_DIR)
  }
}

function checkmd5(path:string, checksum: string) {
  if (!fs.existsSync(path)) { return false; }
  let data = fs.readFileSync(path);
  return nodeCrypto.createHash('md5').update(data).digest('hex') == checksum;
}

ensureDir();
if (!fs.existsSync(VERIFICATUM_FILE) || !checkmd5(CHECKSUM_FILE, VERIFICATUM_MD5)) {
  console.log("Update verificatum lib")
  var options = { url: VERIFICATUM_URL, strictSSL: STRICT_SSL };
  var result = http.get(options).then((result:string, error:Error) => {
    console.log("Update", CHECKSUM_FILE, VERIFICATUM);
    fs.writeFileSync(CHECKSUM_FILE, result);
    fs.writeFileSync(VERIFICATUM, result + '\n\nmodule.exports = verificatum');
    updateLib(VERIFICATUM);
  });
} else {
  console.log(`verificatum lib already exists at ${VERIFICATUM}`)
  updateLib(VERIFICATUM);
}

interface ObjectMap { [s: string]: ObjectMap; }

const TYPES_DIR = 'vendor/@types/verificatum';

function updateLib(loc: string) {
  let mod = path.join(process.cwd(), loc);
  let verificatum:ObjectMap = require(mod);

  function makeModule(lib:string, base:string, key:string, mod:ObjectMap) {
    console.log(`Generate module ${key || 'index'} to ${base}`)
    let prop = key ? `.${key}` : '';
    let code = `// The contents of this file are automatically generated\n`;
    code += `// Modifications to this file are apt to be permanently lost if the code is regenerated.\n\n`;
    code += `const lib = require('${lib}')${prop};\n`
    code += `module.exports = {\n`;
    if (typeof mod == "object") {
      const NESTED_MODULES = ['ec', 'li', 'sli'];
      Object.keys(mod).forEach((name:string) => {
        code += `    ${name}: lib.${name},\n`
        if (NESTED_MODULES.indexOf(name) > -1) {
          let newbase = path.join(base, key);
          let newmod = mod[name];
          let newlib = '../index';
          makeModule(newlib, newbase, name, newmod);
        }
      })
    }
    code += `};`;
    mkdirp.sync(path.join(base, key));
    let typesPath = path.join(base, key, 'index.d.ts');
    if (!fs.existsSync(typesPath)) {
      console.log(`Generate type definition file at ${typesPath}`)
      let typesCode = `export {};`;
      fs.writeFileSync(typesPath, typesCode);
    }
    fs.writeFileSync(path.join(base, key, 'index.js'), code);
  }

  let base = path.dirname(loc);
  makeModule('./lib', base, '', verificatum);
  Object.keys(verificatum).forEach((key:string) => {
    makeModule('../lib', base, key, verificatum[key]);
  })
}
