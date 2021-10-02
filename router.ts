import { Router } from "https://deno.land/x/oak@v8.0.0/mod.ts";
import { getProducts, addProducts } from "./products.ts";
const router = new Router();
router.get("/api/products", getProducts);
router.post("/api/products", addProducts);
export default router;
