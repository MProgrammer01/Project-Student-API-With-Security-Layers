using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc; 
using Microsoft.Extensions.Configuration;
using StudentApi.DataSimulation;
using StudentApi.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace StudentApi.Controllers 
{
    [Authorize] //thid means every endpoint inside this controller requires a valid JWT
    [ApiController] // Marks the class as a Web API controller with enhanced features.
  //  [Route("[controller]")] // Sets the route for this controller to "students", based on the controller name.
    [Route("api/Students")]

    public class StudentsController : ControllerBase // Declare the controller class inheriting from ControllerBase.
    {
        private readonly ILogger<StudentsController> _logger;

        public StudentsController(ILogger<StudentsController> logger)
        {
            _logger = logger;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("All", Name ="GetAllStudents")] // Marks this method to respond to HTTP GET requests.
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        public ActionResult<IEnumerable<Student>> GetAllStudents() // Define a method to get all students.
        {
            //StudentDataSimulation.StudentsList.Clear();

            if (StudentDataSimulation.StudentsList.Count == 0) 
            {
                return NotFound("No Students Found!");
            }
            return Ok(StudentDataSimulation.StudentsList); // Returns the list of students.
        }



        [AllowAnonymous]
        [HttpGet("Passed",Name = "GetPassedStudents")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        // Method to get all students who passed
        public ActionResult<IEnumerable<Student>> GetPassedStudents()

        {
            var passedStudents = StudentDataSimulation.StudentsList.Where(student => student.Grade >= 50).ToList();
            //passedStudents.Clear();

            if (passedStudents.Count == 0)
            {
                return NotFound("No Students Passed");
            }


            return Ok(passedStudents); // Return the list of students who passed.
        }

        [AllowAnonymous]
        [HttpGet("AverageGrade", Name = "GetAverageGrade")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<double> GetAverageGrade()
        {

         //   StudentDataSimulation.StudentsList.Clear();

            if (StudentDataSimulation.StudentsList.Count == 0)
            {
                return NotFound("No students found.");
            }

            var averageGrade = StudentDataSimulation.StudentsList.Average(student => student.Grade);
            return Ok(averageGrade);
        }


        [HttpGet("ID{id}", Name = "GetStudentById")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<Student>> GetStudentById(int id,
            [FromServices] IAuthorizationService authorizationService)
        {
            if (id < 1)
            {
                return BadRequest($"Not accepted ID {id}");
            }

            var student = StudentDataSimulation.StudentsList.FirstOrDefault(s => s.Id == id);
            if (student == null)
            {
                return NotFound($"Student with ID {id} not found.");
            }

            var authResult = await authorizationService.AuthorizeAsync(User,id,"StudentOwnerOrAdmin");

            if (!authResult.Succeeded)
                return Forbid(); // 403


            // If all checks pass:
            // - The user is authenticated
            // - The student exists
            // - The user is either the owner or an admin
            // Access is granted and the student record is returned.

            return Ok(student);
        }

        //for add new we use Http Post
        [Authorize(Roles = "Admin")]
        [HttpPost("Add New Student", Name = "AddStudent")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public ActionResult<Student> AddStudent(Student newStudent)
        {
            //we validate the data here
            if (newStudent == null || string.IsNullOrEmpty(newStudent.Name) || newStudent.Age < 0 || newStudent.Grade < 0)
            {
                return BadRequest("Invalid student data.");
            }

            newStudent.Id = StudentDataSimulation.StudentsList.Count > 0 ? StudentDataSimulation.StudentsList.Max(s => s.Id) + 1 : 1;
            StudentDataSimulation.StudentsList.Add(newStudent);
            
            //we dont return Ok here,we return createdAtRoute: this will be status code 201 created.
            return CreatedAtRoute("GetStudentById", new { id = newStudent.Id }, newStudent);

        }

        //here we use HttpDelete method
        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}", Name = "DeleteStudent")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult DeleteStudent(int id)
        {
            // ✅ Capture IP once for tracing (helps investigations later)
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // ✅ Identify the admin who is performing the action
            // ClaimTypes.NameIdentifier is what you put in JWT during login.
            var adminId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";

            if (id < 1)
            {
                // ✅ Audit attempt (invalid input) - still useful signal
                _logger.LogWarning(
                    "Admin action blocked (invalid id). AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, IP={IP}",
                    adminId,
                    id,
                    ip
                );

                return BadRequest($"Not accepted ID {id}");
            }

            var student = StudentDataSimulation.StudentsList.FirstOrDefault(s => s.Id == id);
            if (student == null)
            {
                // ✅ Audit: admin attempted to delete a non-existing student
                _logger.LogWarning(
                    "Admin action failed (target not found). AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, IP={IP}",
                    adminId,
                    id,
                    ip
                );

                return NotFound($"Student with ID {id} not found.");
            }

            // ===============================
            // Audit BEFORE deleting (recommended)
            // ===============================
            // ✅ Why before?
            // If delete throws or fails later, you still have the audit record of the attempt.
            _logger.LogInformation(
                "Admin action started. AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, TargetEmail={TargetEmail}, IP={IP}",
                adminId,
                student.Id,
                student.Email,
                ip
            );


            StudentDataSimulation.StudentsList.Remove(student);

            // ===============================
            // Audit AFTER deleting (optional, confirms success)
            // ===============================
            _logger.LogInformation(
                "Admin action succeeded. AdminId={AdminId}, Action=DeleteStudent, TargetId={TargetId}, IP={IP}",
                adminId,
                id,
                ip
            );


            return Ok($"Student with ID {id} has been deleted.");
        }

        //here we use http put method for update
        [Authorize(Roles = "Admin")]
        [HttpPut("Update Student By {id}", Name = "UpdateStudent")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<Student> UpdateStudent(int id, Student updatedStudent)
        {
            if (id < 1 || updatedStudent == null || string.IsNullOrEmpty(updatedStudent.Name) || updatedStudent.Age < 0 || updatedStudent.Grade < 0)
            {
                return BadRequest("Invalid student data.");
            }

            var student = StudentDataSimulation.StudentsList.FirstOrDefault(s => s.Id == id);
            if (student == null)
            {
                return NotFound($"Student with ID {id} not found.");
            }

            student.Name = updatedStudent.Name;
            student.Age = updatedStudent.Age;
            student.Grade = updatedStudent.Grade;

            return Ok(student);
        }


    }
}
