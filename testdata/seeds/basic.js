// Small, deterministic starter seed. Add authorized V8/Fuzzilli .js seeds here.
function arithmetic(x) {
  return ((x | 0) * 3 + 7) | 0;
}
for (let i = 0; i < 16; i++) arithmetic(i);
