package com.springsecdemo.web.controllers.studentManagementController;

import com.springsecdemo.data.model.Student;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
    public List<Student> getAllStudents(Student student){
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student){
//        log.info(String.valueOf(student));
        log.info("new students --> {}", student);
    }

    @DeleteMapping(path = {"{studentId}"})
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        log.info("Deleted student",studentId);
    }

    @PutMapping(path = {"{studentId}"})
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        log.info(String.format("%s %s", studentId, student)); 
    }
}
