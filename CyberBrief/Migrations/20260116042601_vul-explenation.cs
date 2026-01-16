using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class vulexplenation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Batch",
                table: "Vulnerabilities",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Explanation",
                table: "Vulnerabilities",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Batch",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "Explanation",
                table: "Vulnerabilities");
        }
    }
}
