using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class init : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Images",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Tag = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    requestId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    scanId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Progres = table.Column<int>(type: "int", nullable: true),
                    SummaryId = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Images", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Summarys",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ImageId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    StartedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    FinishedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    TotalVulnerabilities = table.Column<int>(type: "int", nullable: false),
                    CriticalVulnerabilities = table.Column<int>(type: "int", nullable: false),
                    HighVulnerabilities = table.Column<int>(type: "int", nullable: false),
                    MediumVulnerabilities = table.Column<int>(type: "int", nullable: false),
                    LowVulnerabilities = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Summarys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Package = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Source = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SummaryVulnerabilities",
                columns: table => new
                {
                    SummariesId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    VulnerabilitiesId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SummaryVulnerabilities", x => new { x.SummariesId, x.VulnerabilitiesId });
                    table.ForeignKey(
                        name: "FK_SummaryVulnerabilities_Summarys_SummariesId",
                        column: x => x.SummariesId,
                        principalTable: "Summarys",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SummaryVulnerabilities_Vulnerabilities_VulnerabilitiesId",
                        column: x => x.VulnerabilitiesId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SummaryVulnerabilities_VulnerabilitiesId",
                table: "SummaryVulnerabilities",
                column: "VulnerabilitiesId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Images");

            migrationBuilder.DropTable(
                name: "SummaryVulnerabilities");

            migrationBuilder.DropTable(
                name: "Summarys");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");
        }
    }
}
