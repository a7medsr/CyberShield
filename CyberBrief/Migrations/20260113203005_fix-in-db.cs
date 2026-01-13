using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class fixindb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Vulnerabilities_Summarys_SummaryId",
                table: "Vulnerabilities");

            migrationBuilder.AlterColumn<string>(
                name: "SummaryId",
                table: "Vulnerabilities",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldNullable: true);

            migrationBuilder.AlterColumn<DateTime>(
                name: "StartedAt",
                table: "Summarys",
                type: "datetime2",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<DateTime>(
                name: "FinishedAt",
                table: "Summarys",
                type: "datetime2",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "SummaryId",
                table: "Images",
                type: "nvarchar(max)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddForeignKey(
                name: "FK_Vulnerabilities_Summarys_SummaryId",
                table: "Vulnerabilities",
                column: "SummaryId",
                principalTable: "Summarys",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Vulnerabilities_Summarys_SummaryId",
                table: "Vulnerabilities");

            migrationBuilder.AlterColumn<string>(
                name: "SummaryId",
                table: "Vulnerabilities",
                type: "nvarchar(450)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AlterColumn<string>(
                name: "StartedAt",
                table: "Summarys",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "datetime2");

            migrationBuilder.AlterColumn<string>(
                name: "FinishedAt",
                table: "Summarys",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "datetime2");

            migrationBuilder.AlterColumn<string>(
                name: "SummaryId",
                table: "Images",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(max)",
                oldNullable: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Vulnerabilities_Summarys_SummaryId",
                table: "Vulnerabilities",
                column: "SummaryId",
                principalTable: "Summarys",
                principalColumn: "Id");
        }
    }
}
