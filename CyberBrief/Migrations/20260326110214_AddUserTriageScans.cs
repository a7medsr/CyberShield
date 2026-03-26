using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class AddUserTriageScans : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UserTriageScans",
                columns: table => new
                {
                    TriageScansResourceHash = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UsersId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserTriageScans", x => new { x.TriageScansResourceHash, x.UsersId });
                    table.ForeignKey(
                        name: "FK_UserTriageScans_AspNetUsers_UsersId",
                        column: x => x.UsersId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserTriageScans_TriageCaches_TriageScansResourceHash",
                        column: x => x.TriageScansResourceHash,
                        principalTable: "TriageCaches",
                        principalColumn: "ResourceHash",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserTriageScans_UsersId",
                table: "UserTriageScans",
                column: "UsersId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserTriageScans");
        }
    }
}
