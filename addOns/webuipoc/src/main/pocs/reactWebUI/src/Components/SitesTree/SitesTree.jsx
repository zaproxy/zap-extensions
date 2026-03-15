import { useState, useEffect } from "react";
import Accordion from "../Accordion/AccordionData";
import { sendChildNode } from "../../Utilities/requests";

const SiteTree = () => {
  const [initialSitesTree, setInitialSitesTree] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await sendChildNode("");
        setInitialSitesTree(response);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, []);

  return (
    <div className="flex">
      <div className="w-full bg-gray-600 text-white dark:text-black overflow-auto">
        <div className="h-[1070px] w-[400px] ml-2 bg-gray-800 dark:bg-gray-300 mt-2 rounded-lg overflow-auto ">
          <div className="flex flex-row text-center justify-center ">
            <div className=" w-1/3 p-4 font-serif text-center ">Sites Tree</div>
          </div>
          <div className="flex flex-row  justify-center text-center">
            <div className=" p-4">
              <div className="flex flex-row  justify-center text-center"></div>
              {initialSitesTree &&
                initialSitesTree.map((node) => (
                  <Accordion site={node} fetchChildren={sendChildNode} />
                ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SiteTree;
