import React from "react";

function SearchBar() {
  return (
    <div class="w-full mx-auto bg-gray-600 overflow-hidden p-4">
      <div class="flex items-center border border-black  overflow-hidden">
        <input
          type="text"
          placeholder="Search..."
          class="text-black w-full py-2 px-3 focus:outline-none"
        />
        <button class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2">
          Search
        </button>
      </div>
    </div>
  );
}

export default SearchBar;
