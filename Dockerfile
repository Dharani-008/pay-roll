FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY src/ ./src/
RUN javac -d out src/EmployeePayrollSystem.java

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/out ./out
COPY web/ ./web/
EXPOSE 8080
CMD ["java", "-cp", "out", "EmployeePayrollSystem"]
