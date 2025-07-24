import React from "react";

const Header = () => {
  return (
    <div className="fixed top-0 h-16 left-0 w-full bg-gray-900 text-white z-10">
      <div className="px-4 py-4">
        <div className="flex justify-between items-center">
          <div className="text-xl font-bold">ZAP</div>
          <button className="px-3 py-1 bg-green-600 text-white font-bold ounded-md hover:bg-blue-600">
            Login
          </button>
        </div>
      </div>
    </div>
  );
};

export default Header;
