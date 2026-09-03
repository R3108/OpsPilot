import nextTs from "eslint-config-next/typescript";
import nextVitals from "eslint-config-next/core-web-vitals";

const eslintConfig = [...nextVitals, ...nextTs];

export default eslintConfig;
