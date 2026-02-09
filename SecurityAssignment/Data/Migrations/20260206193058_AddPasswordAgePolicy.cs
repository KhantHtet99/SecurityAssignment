using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurityAssignment.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPasswordAgePolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "ForcePasswordChange",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordLastChangedUtc",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ForcePasswordChange",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "PasswordLastChangedUtc",
                table: "AspNetUsers");
        }
    }
}
