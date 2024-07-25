import React, { useState } from "react";

const Accordion = ({ site, fetchChildren }) => {
    const [isAccordionOpen, setAccordionOpen] = useState(false);
    const [children, setChildren] = useState([])

    const handleExpand = async () => {
        if (isAccordionOpen == false && site.isLeaf == false) {
            const childNodes = await fetchChildren(site.name)
            setChildren(childNodes)
        }
        setAccordionOpen(!isAccordionOpen);
    }
  

  return (
    <div className="py-1 w-[380px]">
      <button
        onClick={handleExpand}
        className="flex justify-between w-full"
      >
        
        <span className="pl-2">
        {site.isLeaf? (
          <span className="mr-3">-</span>
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
            {site.name}
          </span>
        </span>
      </button>
     {
              isAccordionOpen && (
                  <div>
                    <p className="text-blue-200 break-all ml-2 overflow-auto">
                      {
                          children.map((child) => (
                              <Accordion site={child} fetchChildren={fetchChildren}/>
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
