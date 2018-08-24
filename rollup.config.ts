import includePaths from 'rollup-plugin-includepaths';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import sourceMaps from 'rollup-plugin-sourcemaps';
import camelCase from 'lodash.camelcase';
import typescript from 'rollup-plugin-typescript2';

const pkg = require('./package.json');

const libraryName = 'votejs';
const externals = [];
const globals = {
  "crypto": "crypto"
};

export default {
  input: `src/${libraryName}.ts`,
  output: [
    { file: pkg.main, name: camelCase(libraryName), format: 'umd', sourcemap: true, external: externals, globals: globals},
    { file: pkg.module, format: 'es', sourcemap: true, external: externals, globals: globals },
  ],
  // Indicate here external modules you don't wanna include in your bundle (i.e.: 'lodash')
  watch: {
    include: 'src/**',
  },
  plugins: [
    typescript({ useTsconfigDeclarationDir: true }),
    resolve(),
    commonjs(),
    includePaths({
      paths: ['vendor'],
      extensions: ['.js']
    }),
    sourceMaps()
  ],
}
