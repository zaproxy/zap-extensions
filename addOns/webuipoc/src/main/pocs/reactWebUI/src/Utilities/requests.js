import axios from "axios";

const sendChildNode = async (url) => {
  try {
    if (url.length === 0) {
      if (process.env.NODE_ENV === "development") {
        axios.defaults.baseURL = "http://localhost:1337";
      } else {
        axios.defaults.baseURL = "";
      }

      const response = await axios.get("/JSON/core/view/childNodes/");
      return response.data.childNodes;
    } else {
      const response = await axios.get(`/JSON/core/view/childNodes?url=${url}`);
      return response.data.childNodes;
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    throw error;
  }
};

export { sendChildNode };
