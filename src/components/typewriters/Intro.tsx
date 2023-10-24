import React, {useEffect, useState} from "react";
import Typewriter from "typewriter-effect";
import styles from "./intro.module.css"
import {LoadingBar} from "../animations/LoadingBar";
export const Intro: React.FC = props => {
    const [typewriter, setTypewriter] = useState<boolean>(true)
    useEffect(() => {
        setTimeout(() => {setTypewriter(false)}, 5000)
    }, []);
    return (
        <div className={styles.typewriter}>
            {typewriter ? <Typewriter onInit={(typewriter) => {
                typewriter.changeDelay(40)
                    .pauseFor(1000)
                    .typeString('<strong>Itay Chererdman </strong>')
                    .pauseFor(800)
                    .typeString('Portfolio')
                    .start();
            }}/> : <LoadingBar/> }
        </div>
    );
};