# Определяем переменные для путей
TARGET = hash

# Определяем компилятор и флаги компиляции
CXX = g++
CXXFLAGS = -std=c++11 -lcryptopp

# Цель по умолчанию
all: $(TARGET) clean

# Сборка проекта
$(TARGET): $(TARGET).o
	$(CXX) -o $@ $^ $(CXXFLAGS)
	@echo "build complete."

# Правило для компиляции объектных файлов
$(TARGET).o: $(TARGET).cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS)

# Очистка сборки
clean:
	@rm -f ./*.o 
	@echo "clean complete."

.PHONY: all clean
