import AccordionData from '../../Components/Accordion/AccordionData';

const SiteTree = () => { 
return (

    <div className="flex">   
        <div className="w-full bg-gray-600 text-white">
            <div className='h-[1070px] w-[400px] ml-2 bg-gray-800 mt-2 rounded-lg '>
            <div className="flex flex-row text-center justify-center ">
               <div className=" w-1/3 p-4 font-serif text-center ">Sites Tree</div>
            </div>            
            <div className="flex flex-row  justify-center text-center">
                <div className=" p-4" >
                  <p className='font-mono '>Click to fetch</p>
                  <div className="flex flex-row  justify-center text-center">
                </div>
                <AccordionData />
                </div>
            </div>
        </div>
    </div>
    </div>
);
}

export default SiteTree; 
