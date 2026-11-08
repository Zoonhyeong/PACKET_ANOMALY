import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// /api/* 요청을 FastAPI(8000)로 넘김 -> CORS 설정 없이 호출 가능
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
