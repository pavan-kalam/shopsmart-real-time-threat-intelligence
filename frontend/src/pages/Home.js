import React from "react";
import { Link } from "react-router-dom";

function Home() {
  return (
    <div style={{ textAlign: "center", padding: "50px" }}>
      <h1>Welcome to ShopSmart Solutions</h1>
      <p>Secure and user-friendly e-commerce platform</p>
      <Link to="/login">
        <button>Login</button>
      </Link>
    </div>
  );
}

export default Home;
