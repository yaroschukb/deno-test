import { v4 } from "https://deno.land/std@0.95.0/uuid/mod.ts";
import { Product } from "./types.ts";

let products: Product[] = [
  {
    id: "1",
    name: "Product 1",
    description: "This first product",
    price: 30,
  },
  {
    id: "2",
    name: "Product 2",
    description: "This second product",
    price: 40,
  },
  {
    id: "3",
    name: "Product 3",
    description: "This third product",
    price: 50,
  },
  {
    id: "4",
    name: "Product 4",
    description: "This fourth product",
    price: 60,
  },
];

const getProducts = ({ response }: { response: any }) => {
  response.body = {
    success: true,
    data: products,
  };
};
const addProducts = async ({
  request,
  response,
}: {
  request: any;
  response: any;
}) => {
  const body = await request.body();
  if (!request.hasBody) {
    response.body = {
      success: true,
      msg: "No data!",
    };
  } else {
    let product: Product = await body.value;
    product.id = v4.generate();
    products.push(product);
    response.body = {
      success: true,
      data: product,
    };
  }
};

export { getProducts, addProducts };
