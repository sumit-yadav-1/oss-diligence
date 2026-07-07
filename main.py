from dotenv import load_dotenv

from graph.build_graph import build_diligence_graph


def main():
    load_dotenv()

    print("=" * 60)
    print("OSS Dependency Due Diligence Agent")
    print("=" * 60)

    repo_slug = input(
        "GitHub Repository: "
    ).strip()

    package_name = input(
        "Package Name: "
    ).strip()

    ecosystem = (
        input("Ecosystem [PyPI]: ").strip() or "PyPI"
    )

    version = input(
        "Version (optional, press Enter to skip): "
    ).strip()

    graph = build_diligence_graph()

    result = graph.invoke(
        {
            "repo_slug": repo_slug,
            "package_name": package_name,
            "ecosystem": ecosystem,
            "version": version if version else None,
        }
    )

    print("\n" + "=" * 60)
    print("FINAL VERDICT")
    print("=" * 60)

    print(result.get("final_verdict", "No verdict generated"))

    print("\nRecommendation:")
    print(result.get("recommendation", "unknown"))

    print("\nConfidence:")
    print(result.get("verdict_confidence", "unknown"))

    rejected = result.get("rejected_claims", [])

    if rejected:
        print("\nHallucination Guard Flags:")
        for item in rejected:
            print(f"- {item}")


if __name__ == "__main__":
    main()