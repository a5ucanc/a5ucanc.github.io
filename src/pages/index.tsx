import React, {useEffect, useState} from 'react';
import {Intro} from "../components/typewriters/Intro";
import styles from "./Index.module.css"

const Index: React.FC = () => {
    const [intro, setIntro] = useState<boolean>(true)

    useEffect(() => {
        setTimeout(() => {setIntro(false)}, 8200)
    }, []);
    return (
        <div className={`${styles.page} ${intro ? styles.intro : ''}`}>
            {intro && <Intro/>}

        </div>);
}

export default Index;