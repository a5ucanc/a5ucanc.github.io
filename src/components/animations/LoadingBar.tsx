import React from "react";
import styles from "./LoadingBar.module.css"

export const LoadingBar: React.FC = () => {
    return (
        <div>
            <span>Loading...</span>
            <div className={styles.loadingBar}>
                <div className={styles.loadingFill}></div>
            </div>
        </div>
    );
};