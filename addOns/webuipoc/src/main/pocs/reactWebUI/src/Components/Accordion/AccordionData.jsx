import React, { useState, useContext } from "react";
import { nodeIDContext } from "../../Contexts/SitesTreeNodeIDContext";

const Accordion = ({ site, fetchChildren, isChild }) => {
    const [isAccordionOpen, setAccordionOpen] = useState(false);
    const [children, setChildren] = useState([])
    const {setNodeID} = useContext(nodeIDContext)

    const handleExpand = async () => {
      setNodeID (site.hrefId)
        if (isAccordionOpen == false && site.isLeaf == false) {
            const childNodes = await fetchChildren(site.name)
            setChildren(childNodes)
      }
        setAccordionOpen(!isAccordionOpen);
    }
    const getDisplayName = (name) => {
        if (isChild) {
            const parts = name.split('/');
            return parts.length > 1 ? `${parts.slice(-1)[0]}` : name;
        }
        return name;
    };

  return (
    <div className="py-1 w-[380px]">
      <button
        onClick={handleExpand}
        className="flex justify-between w-full">  
        <span className="pl-2">
        {site.isLeaf? (
          <span className="mr-2">• {site.method} :</span>
        ) : (
<> 
      {!isAccordionOpen ? (
          <span className="mr-3">▶</span>
      ) : (
        <span className="mr-3">▼</span>
      )}
    </>
        )}
          <span className="" key={site}>
            {getDisplayName(site.name)}
          </span>
        </span>
      </button>
     {
              isAccordionOpen && (
                  <div>
                    <p className="text-blue-200 dark:text-blue-900 break-all">
                      {
                          children.map((child) => (
                              <Accordion site={child} fetchChildren={fetchChildren} isChild={true}/>
                          )) 
                      }
                      </p>
                      </div>
              )
          }
      </div>

  );
};

export default Accordion;
