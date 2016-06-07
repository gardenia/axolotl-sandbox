#!/bin/bash

CLASSPATH=$(./gradlew -q dump | xargs echo | tr ' ' ':')

java -cp $CLASSPATH:./build/classes/main com.gardenia.App
