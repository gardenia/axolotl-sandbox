
MAIN_CLASS = build/classes/main/com/gardenia/App.class

all: 
	./gradlew build
	
run: $(MAIN_CLASS)
	java -cp $(shell ./gradlew -q dump | xargs echo | tr ' ' ':'):./build/classes/main com.gardenia.App

clean: 
	./gradlew clean

$(MAIN_CLASS):
	./gradlew build
